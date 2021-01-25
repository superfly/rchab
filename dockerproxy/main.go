package main

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/flyctl/api"
)

type ctxKey string

const (
	appNameKey     = ctxKey("app-name")
	accessTokenKey = ctxKey("access-token")
)

var orgSlug = os.Getenv("ALLOW_ORG_SLUG")
var log = logrus.New()
var maxIdleDuration = 10 * time.Minute
var jobDeadline = time.NewTimer(maxIdleDuration)
var buildsWg sync.WaitGroup

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

	ctx, cancel := context.WithCancel(context.Background())

	// Launch `dockerd`
	dockerd := exec.Command("dockerd", "-p", "/var/run/docker.pid")
	dockerd.Stdout = os.Stderr
	dockerd.Stderr = os.Stderr

	if err := dockerd.Start(); err != nil {
		log.Fatalf("could not start dockerd: %v", err)
	}

	dockerDone := make(chan struct{})

	go func() {
		if err := dockerd.Wait(); err != nil {
			log.Errorf("error waiting on docker: %v", err)
		}
		close(dockerDone)
		log.Info("dockerd has exited")
	}()

	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: verifyHost(basicAuth(verifyApp(proxy()))),

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

	if err := httpServer.Shutdown(gracefullCtx); err != nil {
		log.Infof("shutdown error: %v\n", err)
		defer os.Exit(1)
		return
	} else {
		log.Infof("gracefully stopped\n")
	}

	if killSignaled {
		log.Info("Waiting for builds to finish (reason: killSignaled)")
		buildsWg.Wait()
	}

	dockerProc := dockerd.Process
	if dockerProc != nil {
		if err := dockerProc.Signal(os.Interrupt); err != nil {
			log.Errorf("error signaling dockerd to interrupt: %v", err)
		} else {
			log.Info("Waiting for dockerd to exit")
			<-dockerDone
		}
	}

	// manually cancel context if not using httpServer.RegisterOnShutdown(cancel)
	cancel()

	defer os.Exit(0)
}

// check that DOCKER_HOST is tcp://<org slug>:2375
func verifyHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("verifyHost: called")
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
		log.Debugf("verifyHost: host=%s orgSlug=%s", host, orgSlug)
		if host != orgSlug {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		log.Debug("verifyHost: calling next")
		next.ServeHTTP(w, r)
	})
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

		if app.Organization.Slug != orgSlug {
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

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}
