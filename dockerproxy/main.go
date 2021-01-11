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

func main() {
	lvl, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		lvl = logrus.InfoLevel
	}
	logrus.SetLevel(lvl)

	ctx, cancel := context.WithCancel(context.Background())

	// Launch `dockerd`
	dockerd := exec.Command("dockerd", "-p", "/var/run/docker.pid")
	dockerd.Stdout = os.Stderr
	dockerd.Stderr = os.Stderr

	if err := dockerd.Start(); err != nil {
		logrus.Fatalf("could not start dockerd: %v", err)
	}

	dockerDone := make(chan struct{})

	go func() {
		if err := dockerd.Wait(); err != nil {
			logrus.Errorf("error waiting on docker: %v", err)
		}
		close(dockerDone)
		logrus.Info("dockerd has exited")
	}()

	httpServer := &http.Server{
		Addr:        ":8080",
		Handler:     verifyHost(basicAuth(verifyApp(proxy()))),
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	// Run server
	go func() {
		logrus.Infof("Listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			// it is fine to use Fatal here because it is not main gorutine
			logrus.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()

	signalChan := make(chan os.Signal, 1)

	signal.Notify(
		signalChan,
		syscall.SIGINT,
	)

	<-signalChan
	logrus.Info("os.Interrupt - gracefully shutting down...")

	go func() {
		<-signalChan
		logrus.Fatal("os.Kill - abruptly terminating...")
	}()

	gracefullCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	if err := httpServer.Shutdown(gracefullCtx); err != nil {
		logrus.Infof("shutdown error: %v\n", err)
		defer os.Exit(1)
		return
	} else {
		logrus.Infof("gracefully stopped\n")
	}

	dockerProc := dockerd.Process
	if dockerProc != nil {
		if err := dockerProc.Signal(os.Interrupt); err != nil {
			logrus.Errorf("error signaling dockerd to interrupt: %v", err)
		} else {
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
		logrus.Debug("verifyHost: called")
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}
		logrus.Debugf("verifyHost: host=%s orgSlug=%s", host, orgSlug)
		if host != orgSlug {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		logrus.Debug("verifyHost: calling next")
		next.ServeHTTP(w, r)
	})
}

// get app name and access token from Proxy-Authorization
// set them on the request context for later use
func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Debug("basicAuth: called")
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

		logrus.Debugf("basicAuth: app=%s", appName)

		ctx := context.WithValue(context.WithValue(r.Context(), appNameKey, appName), accessTokenKey, accessToken)

		logrus.Debug("basicAuth: calling next")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// retrieve app and validate org is allowed
func verifyApp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Debug("verifyApp: called")
		appName, ok := r.Context().Value(appNameKey).(string)
		if !ok {
			logrus.Error("something is seriously wrong, couldn't get appName")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		accessToken, ok := r.Context().Value(accessTokenKey).(string)
		if !ok {
			logrus.Error("something is seriously wrong, couldn't get accessToken")
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

		logrus.Debug("verifyApp: calling next")
		next.ServeHTTP(w, r)
	})
}

// proxy to docker sock, by hijacking the connection
func proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Debug("proxy: called")
		defer logrus.Debug("proxy: done")
		target := "/var/run/docker.sock"

		var c net.Conn

		cl, err := net.Dial("unix", target)
		if err != nil {
			logrus.Errorf("error connecting to backend: %s", err)
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
			logrus.Infof("hijack error: %v", err)
			return
		}
		defer nc.Close()
		defer c.Close()

		err = r.Write(c)
		if err != nil {
			logrus.Infof("error copying request to target: %v", err)
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
