package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/mitchellh/go-ps"
	"github.com/pkg/errors"
)

const (
	healthCheckTimeout = 10 * time.Second
)

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
	err := os.RemoveAll("/var/run/docker.pid")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, errors.Wrap(err, "could not delete previous docker pid")
	}

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
		return nil, nil, err
	}

	dockerDone := make(chan struct{})

	go func() {
		if err := dockerd.Wait(); err != nil {
			log.Errorf("error waiting on docker: %v", err)
		}
		close(dockerDone)
	}()

	healthCtx, healthCancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer healthCancel()

	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to setup docker clinet")
	}

	stopFn := func() error {
		if dockerd.Process == nil {
			return nil
		}

		tryPrune(context.Background(), dockerClient)
		if err := dockerd.Process.Signal(os.Interrupt); err != nil {
			return err
		}
		<-dockerDone
		log.Info("dockerd has exited")
		return nil
	}

	for {
		log.Info("pinging dockerd")
		_, err := dockerClient.Ping(healthCtx)

		select {
		case <-healthCtx.Done():
			return nil, nil, fmt.Errorf("dockerd failed to boot after %s", healthCheckTimeout)
		case <-dockerDone:
			return nil, nil, fmt.Errorf("dockerd exited before we could ascertain its healthyness")
		default:
			if err != nil {
				log.Errorf("failed to ping dockerd: %v", err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return stopFn, dockerClient, nil

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
