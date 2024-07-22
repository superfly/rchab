package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/gorilla/handlers"
	"github.com/minio/minio/pkg/disk"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"github.com/superfly/flyctl/api"
)

const gb = 1000 * 1000 * 1000

var (
	log             = logrus.New()
	maxIdleDuration = 10 * time.Minute
	jobDeadline     = time.NewTimer(maxIdleDuration)
	pendingRequests atomic.Uint64
	authCache       = cache.New(5*time.Minute, 10*time.Minute)
	keepAlive       = make(chan struct{})

	//prune
	pruneThresholdUsedPercent = 0.8
	pruneThresholdFreeBytes   = 15 * 1000 * 1000 * 1000

	// dev and testing
	noDockerd = os.Getenv("NO_DOCKERD") == "1"
	noAuth    = os.Getenv("NO_AUTH") == "1"
	noAppName = os.Getenv("NO_APP_NAME") == "1"
	noHttps   = os.Getenv("NO_HTTPS") == "1"

	// build variables
	gitSha    string
	buildTime string
)

const (
	DOCKER_LISTENER = "localhost:2376"
	DOCKER_SCHEME   = "http"
	FLY_API_URL     = "https://api.fly.io"
)

var allowedPaths = []*regexp.Regexp{
	regexp.MustCompile("^/flyio/.*$"),
	regexp.MustCompile("^/grpc$"),
	regexp.MustCompile("^/_ping$"),
	regexp.MustCompile("^(/v[0-9.]*)?/info$"),
	regexp.MustCompile("^(/v[0-9.]*)?/images/.*$"),
}

func init() {
	api.SetBaseURL(FLY_API_URL)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)

	sigursChan := make(chan os.Signal, 1)
	signal.Notify(sigursChan, syscall.SIGUSR1)

	go func() {
		for {
			<-sigursChan
			keepAlive <- struct{}{}
		}
	}()

	lvl, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		lvl = logrus.InfoLevel
	}
	log.SetLevel(lvl)
	log.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000000000Z07:00",
		FullTimestamp:   true,
	})

	go func() {
		signal := <-shutdownChan
		if signal == syscall.SIGINT {
			log.Info("os.Kill - abruptly terminating...")
		}
		cancel()
	}()

	log.Infof("Build SHA:%s Time:%s", gitSha, buildTime)

	stopDockerdFn, dockerClient, err := runDockerd()
	if err != nil {
		log.Fatalln(err)
	}

	tryPrune(context.Background(), dockerClient)

	keepAlive := make(chan struct{})
	go watchDocker(ctx, dockerClient, keepAlive)

	httpMux := http.NewServeMux()

	httpMux.Handle("/", wrapCommonMiddlewares(dockerProxy()))
	httpMux.Handle("/flyio/v1/prune", wrapCommonMiddlewares(pruneHandler(dockerClient)))
	httpMux.Handle("/flyio/v1/extendDeadline", wrapCommonMiddlewares((extendDeadline())))
	httpMux.Handle("/flyio/v1/buildOverlaybdImage", wrapCommonMiddlewares(overlaybdImageHandler()))
	httpMux.Handle("/flyio/v1/settings", wrapCommonMiddlewares(settingsHandler()))

	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: httpMux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},

		// keep these as high as possible. shorter read/write timeouts can cause push operations
		// for large images to hang midway with the error -> context.Cancelled.
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
	}
	httpServer.RegisterOnShutdown(cancel)

	go func() {
		log.Infof("Listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("failed to listenAndServe on %s: %v", httpServer.Addr, err)
		}
	}()

	httpServer2 := &http.Server{
		Addr:    ":2375",
		Handler: dockerProxy(),
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},

		// keep these as high as possible. shorter read/write timeouts can cause push operations
		// for large images to hang midway with the error -> context.Cancelled.
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
	}
	httpServer2.RegisterOnShutdown(cancel)

	go func() {
		log.Infof("Listening on %s", httpServer2.Addr)
		if err := httpServer2.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("failed to listenAndServe on %s: %v", httpServer2.Addr, err)
		}
	}()

	go func() {
		for {
			select {
			case <-keepAlive:
			case <-jobDeadline.C:
				if pendingRequests.Load() == 0 {
					log.Info("deadline reached, no active builds, shutting down")
					cancel()
					return
				}
				log.Infof("can't shutdown yet, still have %d pending requests", pendingRequests.Load())
			}
			log.Debug("liveness loop caused deadline reset")
			jobDeadline.Reset(maxIdleDuration)
		}
	}()

	<-ctx.Done()

	log.Info("init shutdown")

	gracefullCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()

	log.Info("shutting down proxy")
	if err := httpServer.Shutdown(gracefullCtx); err != nil {
		log.Warnf("shutdown error on %s: %v\n", httpServer.Addr, err)
		os.Exit(1)
	}

	log.Info("shutting down proxy2")
	if err := httpServer2.Shutdown(gracefullCtx); err != nil {
		log.Warnf("shutdown error on %s: %v\n", httpServer2.Addr, err)
		os.Exit(1)
	}

	log.Info("shutting down docker")
	stopDockerdFn()

	log.Info("shutdown complete")
	os.Exit(0)
}

func extendDeadline() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Infof("extendDeadline called with user agent: %s", r.UserAgent())

		before, err := disk.GetInfo("/data")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Errorf("failed to check /data: %s", err)
			return
		}

		// prune only if the storage space is too low.
		err = newInsufficientStorageError(before)
		if err != nil {
			client, err := client.NewEnvClient()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Errorf("failed to create a Docker client: %s", err)
				return
			}

			prune(context.Background(), client, "1m")
		}

		// return error if pruning is not enough.
		after, err := disk.GetInfo("/data")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Errorf("failed to check /data: %s", err)
			return
		}

		err = newInsufficientStorageError(after)
		if err != nil {
			w.WriteHeader(http.StatusInsufficientStorage)
			w.Write([]byte(err.Error()))
			return
		}

		defer func() {
			jobDeadline.Reset(maxIdleDuration)

		}()
		w.WriteHeader(http.StatusAccepted)
	})
}

func dockerProxy() http.Handler {
	reverseProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: DOCKER_SCHEME,
		Host:   DOCKER_LISTENER,
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pendingRequests.Add(1)

		allowed := false
		for _, allowedPath := range allowedPaths {
			if allowedPath.MatchString(r.URL.Path) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Warnf("Refusing to proxy %s", r.URL)
			http.Error(w, `{"message":"page not found"}`, http.StatusNotFound)
			return
		}

		defer func() {
			pendingRequests.Add(^uint64(0))
		}()

		reverseProxy.ServeHTTP(w, r)
	})
}

func pruneHandler(client *client.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		until := strings.TrimSpace(r.URL.Query().Get("since"))
		if until == "" {
			until = "1s"
		}

		prune(r.Context(), client, until)
		w.WriteHeader(http.StatusOK)
	})
}

func settingsHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(map[string]bool{
			"supports_wgless_deployment": true,
		})
		if err != nil {
			log.Warnln("error writing settings response", err)
			return
		}
	})
}

func upgradeToHTTPs(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !noHttps && r.Header.Get("X-Forwarded-Proto") == "http" {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func wrapCommonMiddlewares(h http.Handler) http.Handler {
	return handlers.LoggingHandler(
		log.Writer(),
		upgradeToHTTPs(
			authRequest(
				h,
			),
		),
	)
}
