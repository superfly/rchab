package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/gorilla/handlers"
	"github.com/minio/minio/pkg/disk"
	"github.com/mitchellh/go-ps"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
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

	//prune
	pruneThresholdUsedPercent = 0.8
	pruneThresholdFreeBytes   = 15 * 1000 * 1000 * 1000

	// dev and testing
	noDockerd = os.Getenv("NO_DOCKERD") == "1"
	noAuth    = os.Getenv("NO_AUTH") == "1"
	noAppName = os.Getenv("NO_APP_NAME") == "1"

	// build variables
	gitSha    string
	buildTime string
)

const (
	DOCKER_LISTENER = "localhost:2375"
	DOCKER_SCHEME   = "http"
	FLY_API_URL     = "https://api.fly.io"
)

func init() {
	api.SetBaseURL(FLY_API_URL)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)

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
	httpMux.Handle("/", handlers.LoggingHandler(log.Writer(), authRequest(proxy())))
	httpMux.Handle("/flyio/v1/extendDeadline", handlers.LoggingHandler(log.Writer(), authRequest(extendDeadline())))
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
			log.Fatalf("failed to listenAndServe: %v", err)
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
		log.Warnf("shutdown error: %v\n", err)
		os.Exit(1)
	}

	log.Info("shutting down proxy")
	stopDockerdFn()

	log.Info("shutdown complete")
	os.Exit(0)
}

func runDockerd() (func() error, *client.Client, error) {
	// noop
	if noDockerd {
		client, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			return nil, nil, err
		}
		return func() error { return nil }, client, nil
	}

	// just to be sure, because machines now reuse snapshots
	os.RemoveAll("/var/run/docker.pid")

	// Launch `dockerd`
	dockerd := exec.Command("dockerd", "-p", "/var/run/docker.pid")
	dockerd.Stdout = os.Stderr
	dockerd.Stderr = os.Stderr

	if err := dockerd.Start(); err != nil {
		return nil, nil, errors.Wrap(err, "could not start dockerd")
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
	}()

	healthCtx, healthCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer healthCancel()

	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to setup docker clinet")
	}

	stopFn := func() error {
		if dockerd.Process != nil {
			tryPrune(context.Background(), dockerClient)
			if err := dockerd.Process.Signal(os.Interrupt); err != nil {
				return err
			}
			<-dockerDone
			log.Info("dockerd has exited")
			return nil
		}
		return nil
	}

	for {
		log.Info("pinging dockerd")
		resp, err := dockerClient.Ping(healthCtx)

		select {
		case <-healthCtx.Done():
			return nil, nil, fmt.Errorf("dockerd failed to boot after 10 seconds")
		case <-dockerDone:
			return nil, nil, fmt.Errorf("dockerd exited before we could ascertain its healthyness")
		default:
			if err != nil {
				log.Errorf("failed to ping dockerd: %v", err)
				time.Sleep(200 * time.Millisecond)
			}
			if resp.APIVersion != "" {
				return stopFn, dockerClient, nil
			}
		}
	}
}

// tryPrune frees disk space if necessary
func tryPrune(ctx context.Context, dockerClient *client.Client) {
	di, err := disk.GetInfo("/data")
	if err != nil {
		log.Errorf("could not get disk usage: %v", err)
		return
	}

	percentUsed := (float64(di.Total-di.Free) / float64(di.Total))
	log.Infof("disk space used: %0.2f%%", percentUsed*100)
	if percentUsed >= pruneThresholdUsedPercent || di.Free <= uint64(pruneThresholdFreeBytes) {
		log.Info("Not enough disk space, pruning")
		prune(ctx, dockerClient, "12h")
	}
}

func prune(ctx context.Context, dockerClient *client.Client, until string) {
	imgReport, err := dockerClient.ImagesPrune(ctx, filters.NewArgs(
		// Remove images created before the duration string (e.g. 12h).
		filters.Arg("until", until),

		// Remove all images, not just dangling ones.
		// https://github.com/moby/moby/blob/f117aef2ea63ee008c05a7506c8c9c50a1fa0c7f/docs/api/v1.43.yaml#L8677
		filters.Arg("dangling", "false"),
	))
	if err != nil {
		log.Errorf("error pruning images: %v", err)
	} else {
		log.Infof("Pruned %d bytes of images", imgReport.SpaceReclaimed)
	}

	volReport, err := dockerClient.VolumesPrune(ctx, filters.NewArgs())
	if err != nil {
		log.Errorf("error pruning volumes: %v", err)
	} else {
		log.Infof("Pruned %d bytes of volumes", volReport.SpaceReclaimed)
	}

	bcReport, err := dockerClient.BuildCachePrune(ctx, types.BuildCachePruneOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("until", until)),
	})

	if err != nil {
		log.Errorf("error pruning build cache: %v", err)
	} else {
		log.Infof("Pruned %d bytes from build cache", bcReport.SpaceReclaimed)
	}
}

func watchDocker(ctx context.Context, dockerClient *client.Client, keepaliveCh chan<- struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dActive, err := isDockerActive(ctx, dockerClient)
			if err != nil {
				log.Error("failed to check for docker activeness", err)
				return
			}
			bActive, err := isBuildkitActive()
			if err != nil {
				log.Error("failed to check for buildkit activeness", err)
				return
			}
			if dActive && bActive {
				keepaliveCh <- struct{}{}
			}
		}
	}
}

// buildkit containers don't show up in dockerd, since we're not running
// buildkitd just look for runc processes which are spawned by buildkit builders
func isBuildkitActive() (bool, error) {
	processes, err := ps.Processes()
	if err != nil {
		return false, err
	}

	for _, p := range processes {
		if p.Executable() == "runc" {
			return true, nil
		}
	}

	return false, nil
}

func isDockerActive(ctx context.Context, dockerClient *client.Client) (status bool, err error) {
	containers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{Filters: filters.NewArgs(filters.Arg("status", "running"))})
	if err != nil {
		return false, err
	}
	return len(containers) > 0, nil
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

// TODO: If we know that we're always going to use 6pn to access builders, we can probably just drop this auth since the network will take care to authorize access within the same org?
func authorizeRequest(appName, authToken string) bool {
	fly := api.NewClient(authToken, fmt.Sprintf("superfly/rchab/%s", gitSha), "0.0.0.0.0.0.1", log)

	app, err := fly.GetAppCompact(context.TODO(), appName)
	if app == nil || err != nil {
		log.Warnf("Error fetching app %s: %v", appName, err)
		return false
	}

	// local dev only: we started machine with NO_APP_NAME=1, skip checking that appName from auth is in same org as this builder
	if noAppName {
		log.Warnf("Skipping organization check for app %s on builder", appName)
		return true
	}

	builderAppName, ok := os.LookupEnv("FLY_APP_NAME")
	if !ok {
		log.Warn("FLY_APP_NAME env var is not set!")
		return false
	}
	builderApp, err := fly.GetAppCompact(context.TODO(), builderAppName)
	if builderApp == nil || err != nil {
		log.Warnf("Error fetching builder app %s", builderAppName)
		return false
	}
	if app.Organization.ID != builderApp.Organization.ID {
		log.Warnf("App %s is in %s org, and builder %s is in %s org", appName, app.Organization.Slug, builderAppName, builderApp.Organization.Slug)
		return false
	}

	appOrg, err := fly.GetOrganizationBySlug(context.TODO(), app.Organization.Slug)
	if appOrg == nil || err != nil {
		log.Warnf("Error fetching org %s: %v", app.Organization.Slug, err)
		return false
	}
	builderOrg, err := fly.GetOrganizationBySlug(context.TODO(), builderApp.Organization.Slug)
	if builderOrg == nil || err != nil {
		log.Warnf("Error fetching org %s: %v", builderApp.Organization.Slug, err)
		return false
	}

	if app.Organization.ID != builderApp.Organization.ID {
		log.Warnf("App %s does not belong to org %s (builder app: '%s' builder org: '%s')", app.Name, appOrg.Slug, builderAppName, builderOrg.Slug)
		return false
	}

	return true
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

func proxy() http.Handler {
	reverseProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: DOCKER_SCHEME,
		Host:   DOCKER_LISTENER,
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pendingRequests.Add(1)

		defer func() {
			pendingRequests.Add(^uint64(0))
		}()

		reverseProxy.ServeHTTP(w, r)
	})
}
