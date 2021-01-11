module github.com/superfly/rchab/dockerproxy

go 1.15

require (
	github.com/docker/docker v1.4.2-0.20200227233006-38f52c9fec82
	github.com/sirupsen/logrus v1.7.0
	github.com/superfly/flyctl v0.0.158
)

replace github.com/containerd/containerd => github.com/containerd/containerd v1.3.1-0.20200227195959-4d242818bf55

replace github.com/docker/docker => github.com/docker/docker v1.4.2-0.20200227233006-38f52c9fec82
