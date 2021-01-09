package main

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/superfly/flyctl/api"
)

func main() {
	logrus.Fatal(http.ListenAndServe(":8080", basicAuth(proxy())))
}

func basicAuth(h http.Handler) http.Handler {
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

		api.SetBaseURL("https://api.fly.io")
		fly := api.NewClient(accessToken, "0.0.0.0.0.0.1")
		app, err := fly.GetApp(appName)
		if app == nil || err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("App not found"))
			return
		}

		if app.Organization.Slug != os.Getenv("ALLOW_ORG_SLUG") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Wrong organization"))
			return
		}

		h.ServeHTTP(w, r)
	})
}

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
