package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/superfly/flyctl/api"
)

var (
	orgSlug         = os.Getenv("ALLOW_ORG_SLUG")
	log             = logrus.New()
	maxIdleDuration = 10 * time.Minute
	jobDeadline     = time.NewTimer(maxIdleDuration)
	buildsWg        sync.WaitGroup
	pendingRequests uint64
	authCache       = cache.New(5*time.Minute, 10*time.Minute)

	// dev and testing
	noDockerd = os.Getenv("NO_DOCKERD") == "1"
	noAuth    = os.Getenv("NO_AUTH") == "1"

	// build variables
	gitSha    string
	buildTime string
)

var bufPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 1<<20)
		return &buffer
	},
}

const DOCKER_SOCKET_PATH = "/var/run/docker.sock"

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
		Handler: handlers.LoggingHandler(log.Writer(), authRequest(proxy())),

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
			log.Info("received SIGUSR1")
			break
		case <-jobDeadline.C:
			log.Info("Deadline reached without docker build")
			// job deadline reached AND no pending requests!
			if atomic.LoadUint64(&pendingRequests) == 0 {
				break ALIVE
			}
			log.Infof("still requests pendings: %d", atomic.LoadUint64(&pendingRequests))
			break
		case <-killSig:
			killSignaled = true
			log.Info("os.Interrupt - gracefully shutting down...")
			go func() {
				<-killSig
				log.Fatal("os.Kill - abruptly terminating...")
			}()
			// got a kill signal, so we're kinda done!
			break ALIVE
		}
		log.Debug("liveness loop caused deadline reset")
		// reset the deadline if we get here
		jobDeadline.Reset(maxIdleDuration)
	}

	log.Info("shutting down")

	gracefullCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	if err := httpServer.Shutdown(gracefullCtx); err != nil {
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

	cmd := exec.Command("docker", "buildx", "inspect", "--bootstrap")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Warnln("Error bootstrapping buildx builder:", err)
	}

	dockerDone := make(chan struct{})

	go func() {
		if err := dockerd.Wait(); err != nil {
			log.Errorf("error waiting on docker: %v", err)
		}
		close(dockerDone)
		log.Info("dockerd has exited")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", DOCKER_SOCKET_PATH)
			},
		},
	}

OUTER:
	for {
		log.Debug("Checking dockerd healthyness")
		errCh := make(chan error, 1)

		go func() {
			_, err := client.Head("http://localhost/_ping")
			errCh <- err
		}()

		select {
		case err := <-errCh:
			if err != nil {
				log.Debugf("got error pinging dockerd: %v", err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			break OUTER
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout elapsed while trying to check dockerd healthiness")
		case <-dockerDone:
			return nil, fmt.Errorf("dockerd exited before we could ascertain its healthyness")
		}
	}

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

func authRequest(next http.Handler) http.Handler {
	if noAuth {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appName, authToken, ok := r.BasicAuth()

		if !ok || !authorizeRequestWithCache(appName, authToken) {
			if err := writeDockerDaemonResponse2(w, http.StatusUnauthorized, "You are not authorized to use this builder"); err != nil {
				log.Warnln("error writing response", err)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeDockerDaemonResponse2(w http.ResponseWriter, status int, message string) error {
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func authorizeRequestWithCache(appName, authToken string) bool {
	if noAuth {
		return true
	}

	if appName == "" || authToken == "" {
		return false
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
		log.Warnf("Error fetching app %s: %v", appName, err)
		return false
	}

	org, err := fly.FindOrganizationBySlug(orgSlug)
	if org == nil || err != nil {
		log.Warnf("Error fetching org %s: %v", orgSlug, err)
		return false
	}

	if app.Organization.ID != org.ID {
		log.Warnf("App %s does not belong to org %s", app.Name, org.Slug)
		return false
	}

	return true
}

// proxy to docker sock, by hijacking the connection
func proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("proxy: called")
		atomic.AddUint64(&pendingRequests, 1)
		buildsWg.Add(1)
		defer buildsWg.Done()

		defer func() {
			atomic.AddUint64(&pendingRequests, ^uint64(0))
		}()

		defer func() {
			log.Debug("resetting deadline")
			jobDeadline.Reset(maxIdleDuration)
		}()
		defer log.Debug("proxy: done")

		if err := proxyDocker(w, r); err != nil {
			log.Error(err)
		}
	})
}

func proxyDocker(w http.ResponseWriter, r *http.Request) error {
	c, err := net.Dial("unix", DOCKER_SOCKET_PATH)
	if err != nil {
		return fmt.Errorf("error connecting to backend: %s", err)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack error", 500)
		return fmt.Errorf("could not hijack connection")
	}
	nc, _, err := hj.Hijack()
	if err != nil {
		log.Infof("hijack error: %v", err)
		return fmt.Errorf("error hikacking connection: %v", err)
	}

	defer nc.Close()
	defer c.Close()

	err = r.Write(c)
	if err != nil {
		return fmt.Errorf("error copying request to target: %v", err)
	}

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader, label string) {
		_, err := copyWithBuffer(dst, src)
		if err != nil {
			log.Errorf("error copying %s: %v", label, err)
		}
		errc <- err
	}
	go cp(c, nc, "client->docker")
	go cp(nc, c, "docker->client")
	return <-errc
}

// copyWithBuffer is very similar to  io.CopyBuffer https://golang.org/pkg/io/#CopyBuffer
// but instead of using Read to read from the src, we use ReadAtLeast to make sure we have
// a full buffer before we do a write operation to dst to reduce overheads associated
// with the write operations of small buffers.
// Taken from https://github.com/amrmahdi/containerd/blob/b81917ee72a8e705127006084619b5c0ef76aa8e/content/helpers.go#L236
func copyWithBuffer(dst io.Writer, src io.Reader) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}
	bufRef := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufRef)
	buf := *bufRef
	for {
		nr, er := io.ReadAtLeast(src, buf, len(buf))
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil { // If an EOF happens after reading fewer than the requested bytes,
			// ReadAtLeast returns ErrUnexpectedEOF.
			if er != io.EOF && er != io.ErrUnexpectedEOF {
				err = er
			}
			break
		}
	}
	return
}
