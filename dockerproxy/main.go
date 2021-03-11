package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/superfly/flyctl/api"

	gossh "golang.org/x/crypto/ssh"
)

type ctxKey string

const (
	appNameKey     = ctxKey("app-name")
	accessTokenKey = ctxKey("access-token")
)

var (
	orgSlug         = os.Getenv("ALLOW_ORG_SLUG")
	log             = logrus.New()
	maxIdleDuration = 10 * time.Minute
	jobDeadline     = time.NewTimer(maxIdleDuration)
	buildsWg        sync.WaitGroup
	authCache       = cache.New(5*time.Minute, 10*time.Minute)

	// dev and testing
	noDockerd = os.Getenv("NO_DOCKERD") == "1"
	noAuth    = os.Getenv("NO_AUTH") == "1"

	// build variables
	gitSha    string
	buildTime string
)

func main() {
	lvl, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		lvl = logrus.InfoLevel
	}
	log.SetLevel(lvl)
	log.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000000000Z07:00",
		FullTimestamp:   true,
	})

	log.Infof("Build SHA:%s Time:%s", gitSha, buildTime)

	api.SetBaseURL("https://api.fly.io")

	ctx, cancel := context.WithCancel(context.Background())

	stopDockerdFn, err := runDockerd()
	if err != nil {
		log.Fatalln(err)
	}

	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: basicAuth(verifyApp(proxy())),

		// reuse the context we've created
		BaseContext: func(_ net.Listener) context.Context { return ctx },

		// kosher timeouts
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Run server
	go func() {
		log.Infof("Listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			// it is fine to use Fatal here because it is not main gorutine
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()

	privateKeyPath := "id_rsa"
	if dataDir, ok := os.LookupEnv("DATA_DIR"); ok {
		privateKeyPath = filepath.Join(dataDir, privateKeyPath)
	}

	pk, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		log.Println("Error loading private key, generating new keys", err)
		pk, err = generatePrivateKey(privateKeyPath)
		if err != nil {
			log.Fatalln("Failed to generate private key", err)
		}
	}

	signer, err := gossh.NewSignerFromKey(pk)

	sshServer := &ssh.Server{
		Addr:        ":2222",
		Handler:     sshHandler,
		HostSigners: []ssh.Signer{signer},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			return authorizeRequestWithCache(ctx.User(), password)
		},
	}

	// Run server
	go func() {
		log.Infoln("ssh proxy listening on", sshServer.Addr)
		if err := sshServer.ListenAndServe(); err != ssh.ErrServerClosed {
			log.Fatalln("ssh server ListenAndServe", err)
		}
	}()

	killSig := make(chan os.Signal, 1)

	signal.Notify(
		killSig,
		syscall.SIGINT,
	)

	var killSignaled bool

	keepAliveSig := make(chan os.Signal, 1)
	signal.Notify(
		keepAliveSig,
		syscall.SIGUSR1,
	)

ALIVE:
	for {
		select {
		case <-keepAliveSig:
			log.Info("received SIGUSR1, resetting job deadline")
			jobDeadline.Reset(maxIdleDuration)
		case <-jobDeadline.C:
			log.Info("Deadline reached without docker build - shutting down...")
			break ALIVE
		case <-killSig:
			killSignaled = true
			log.Info("os.Interrupt - gracefully shutting down...")
			go func() {
				<-killSig
				log.Fatal("os.Kill - abruptly terminating...")
			}()
			break ALIVE
		}
	}

	log.Info("shutting down")

	gracefullCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	if err := sshServer.Shutdown(gracefullCtx); err != nil {
		log.Warnf("shutdown error: %v\n", err)
		defer os.Exit(1)
		return
	} else {
		log.Infof("gracefully stopped\n")
	}

	if killSignaled {
		log.Info("Waiting for builds to finish (reason: killSignaled)")
		buildsWg.Wait()
	}

	stopDockerdFn()

	// manually cancel context if not using httpServer.RegisterOnShutdown(cancel)
	cancel()

	defer os.Exit(0)
}

func runDockerd() (func(), error) {
	// noop
	if noDockerd {
		return func() {}, nil
	}

	// Launch `dockerd`
	dockerd := exec.Command("dockerd", "-p", "/var/run/docker.pid")
	dockerd.Stdout = os.Stderr
	dockerd.Stderr = os.Stderr

	if err := dockerd.Start(); err != nil {
		return nil, errors.Wrap(err, "could not start dockerd")
	}

	dockerDone := make(chan struct{})

	go func() {
		if err := dockerd.Wait(); err != nil {
			log.Errorf("error waiting on docker: %v", err)
		}
		close(dockerDone)
		log.Info("dockerd has exited")
	}()

	stopFn := func() {
		dockerProc := dockerd.Process
		if dockerProc != nil {
			if err := dockerProc.Signal(os.Interrupt); err != nil {
				log.Errorf("error signaling dockerd to interrupt: %v", err)
			} else {
				log.Info("Waiting for dockerd to exit")
				<-dockerDone
			}
		}
	}

	return stopFn, nil
}

// get app name and access token from Proxy-Authorization
// set them on the request context for later use
func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("basicAuth: called")
		proxyauth := r.Header.Get("Proxy-Authorization")
		if proxyauth == "" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		appName, accessToken, ok := parseBasicAuth(proxyauth)
		if !ok {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}

		log.Debugf("basicAuth: app=%s", appName)

		ctx := context.WithValue(context.WithValue(r.Context(), appNameKey, appName), accessTokenKey, accessToken)

		log.Debug("basicAuth: calling next")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// retrieve app and validate org is allowed
func verifyApp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("verifyApp: called")
		appName, ok := r.Context().Value(appNameKey).(string)
		if !ok {
			log.Error("something is seriously wrong, couldn't get appName")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		accessToken, ok := r.Context().Value(accessTokenKey).(string)
		if !ok {
			log.Error("something is seriously wrong, couldn't get accessToken")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		api.SetBaseURL("https://api.fly.io")
		fly := api.NewClient(accessToken, "0.0.0.0.0.0.1")
		app, err := fly.GetApp(appName)
		if app == nil || err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("App not found"))
			return
		}

		org, err := fly.FindOrganizationBySlug(orgSlug)
		if org == nil || err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Organization not found"))
			return
		}

		if app.Organization.ID != org.ID {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Wrong organization"))
			return
		}

		log.Debug("verifyApp: calling next")
		next.ServeHTTP(w, r)
	})
}

// proxy to docker sock, by hijacking the connection
func proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("proxy: called")
		defer log.Debug("proxy: done")
		defer func() {
			log.Debug("resetting deadline")
			jobDeadline.Reset(maxIdleDuration)
		}()

		target := "/var/run/docker.sock"

		var c net.Conn

		cl, err := net.Dial("unix", target)
		if err != nil {
			log.Errorf("error connecting to backend: %s", err)
			return
		}

		c = cl
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack error", 500)
			return
		}
		nc, _, err := hj.Hijack()
		if err != nil {
			log.Infof("hijack error: %v", err)
			return
		}

		buildsWg.Add(1)
		defer buildsWg.Done()

		defer nc.Close()
		defer c.Close()

		err = r.Write(c)
		if err != nil {
			log.Infof("error copying request to target: %v", err)
			return
		}

		errc := make(chan error, 2)
		cp := func(dst io.Writer, src io.Reader) {
			_, err := io.Copy(dst, src)
			errc <- err
		}
		go cp(c, nc)
		go cp(nc, c)
		<-errc
	})
}

func sshHandler(s ssh.Session) {
	log.Infoln("starting session for", s.RemoteAddr())

	defer func() {
		log.Debug("resetting deadline")
		jobDeadline.Reset(maxIdleDuration)
	}()

	dockerConn, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		log.Errorln("error connecting to docker daemon:", err)
		writeDockerDaemonResponse(s, http.StatusInternalServerError, errors.Wrap(err, "Unable to connect to the docker daemon").Error())
		return
	}
	log.Infoln("connected to docker")

	buildsWg.Add(1)
	defer buildsWg.Done()

	defer dockerConn.Close()

	done := make(chan error)

	// client -> docker
	go func() {
		sock := dockerConn.(*net.UnixConn)
		n, err := io.Copy(sock, s)
		log.Debugf("%s client->docker: copied %d bytes: %v", s.RemoteAddr(), n, err)
		sock.CloseWrite()
	}()

	// docker -> client
	go func() {
		n, err := io.Copy(s, dockerConn)
		log.Debugf("%s client<-docker: copied %d bytes: %v", s.RemoteAddr(), n, err)
		s.CloseWrite()

		done <- err
	}()

	log.Infoln("waiting for session to end", s.RemoteAddr())

	if err := <-done; err != nil {
		log.Warnln("Error writing to client", err)
	}

	log.Infoln("finished session", s.RemoteAddr())
}

func writeDockerDaemonResponse(w io.Writer, status int, message string) error {
	var body bytes.Buffer
	json.NewEncoder(&body).Encode(map[string]string{"message": message})

	r := http.Response{
		StatusCode: status,
		Body:       io.NopCloser(&body),
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}

	return r.Write(w)
}

func authorizeRequestWithCache(appName, authToken string) bool {
	if noAuth {
		return true
	}

	cacheKey := appName + ":" + authToken
	if val, ok := authCache.Get(cacheKey); ok {
		if authorized, ok := val.(bool); ok {
			log.Debugln("authorized from cache")
			return authorized
		}
	}

	authorized := authorizeRequest(appName, authToken)
	authCache.Set(cacheKey, authorized, 0)
	log.Debugln("authorized from api")
	return authorized
}

func authorizeRequest(appName, authToken string) bool {
	fly := api.NewClient(authToken, "0.0.0.0.0.0.1")
	app, err := fly.GetApp(appName)
	if app == nil || err != nil {
		log.Warnf("Error fetching app %s:", appName, err)
		return false
	}

	org, err := fly.FindOrganizationBySlug(orgSlug)
	if org == nil || err != nil {
		log.Warnf("Error fetching org %s:", orgSlug, err)
		return false
	}

	if app.Organization.ID != org.ID {
		log.Warnf("App %s does not belong to org %s", app.Name, org.Slug)
		return false
	}

	return true
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	auth = strings.TrimPrefix(strings.TrimPrefix(auth, "Basic "), "basic ")
	c, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		log.Warnln("Error decoding auth", err)
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("Expected \"RSA PRIVATE KEY\" found \"%s\"", block.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Errror parsing private key")
	}

	return privateKey, nil
}

func generatePrivateKey(filename string) (*rsa.PrivateKey, error) {
	// generate key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot generate RSA key")
	}

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(filename)
	if err != nil {
		return nil, errors.Wrap(err, "error creating private.pem")
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return nil, errors.Wrap(err, "error encoding private pem")
	}

	return privatekey, nil
}
