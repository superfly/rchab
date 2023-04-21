package main

import (
	"testing"

	"github.com/minio/minio/pkg/disk"
)

func TestError(t *testing.T) {
	info := disk.Info{
		Total: 100 * gb,
		Free:  99 * gb,
	}

	err := newInsufficientStorageError(info)
	if err != nil {
		t.Errorf("expected nil, but got %v", err)
	}
}
