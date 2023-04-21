package main

import (
	"fmt"
	"github.com/minio/minio/pkg/disk"
)

func newInsufficientStorageError(di disk.Info) error {
	if di.Free <= uint64(1*gb) {
		free := float64(di.Free) / float64(gb)
		return fmt.Errorf("remaining disk space (%.2fGB) is too low", free)
	}

	percentUsed := (float64(di.Total-di.Free) / float64(di.Total))
	if percentUsed >= pruneThresholdUsedPercent {
		return fmt.Errorf("remaining disk space (%.2f%%) is too low", percentUsed)
	}

	return nil
}
