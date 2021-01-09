package main

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/superfly/flyctl/api"
)

type ctxKey string

var (
	appNameKey     = ctxKey("app-name")
	accessTokenKey = ctxKey("access-token")
)

var orgSlug = os.Getenv("ALLOW_ORG_SLUG")

func main() {
	logrus.Fatal(http.ListenAndServe(":8080", verifyHost(basicAuth(verifyApp(proxy())))))
}

// check that DOCKER_HOST is tcp://<org slug>:2375
func verifyHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != orgSlug {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// get app name and access token from Proxy-Authorization
// set them on the request context for later use
func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.Infof("%s %s", r.Method, r.URL)
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

		ctx := context.WithValue(context.WithValue(r.Context(), appNameKey, appName), accessTokenKey, accessToken)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// retrieve app and validate org is allowed
func verifyApp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		next.ServeHTTP(w, r)
	})
}

// proxy to docker sock, by hijacking the connection
func proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			logrus.Printf("hijack error: %v", err)
			return
		}
		defer nc.Close()
		defer c.Close()

		err = r.Write(c)
		if err != nil {
			logrus.Printf("error copying request to target: %v", err)
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
