module github.com/superfly/rchab/dockerproxy

go 1.16

require (
	github.com/containerd/containerd v1.4.1-0.20201117152358-0edc412565dc // indirect
	github.com/docker/docker v20.10.6+incompatible
	github.com/gorilla/handlers v1.5.1
	github.com/minio/minio v0.0.0-20210516060309-ce3d9dc9faa5
	github.com/mitchellh/go-ps v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.0
	github.com/superfly/flyctl v0.0.163
)

replace github.com/containerd/containerd => github.com/containerd/containerd v1.3.1-0.20200227195959-4d242818bf55

replace github.com/docker/docker => github.com/docker/docker v1.4.2-0.20200227233006-38f52c9fec82
