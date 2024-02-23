package main

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/minio/minio/pkg/disk"
)

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
