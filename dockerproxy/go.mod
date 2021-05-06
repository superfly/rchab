module github.com/superfly/rchab/dockerproxy

go 1.16

require (
	github.com/containerd/containerd v1.4.1-0.20201117152358-0edc412565dc // indirect
	github.com/docker/docker v20.10.6+incompatible
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/mitchellh/go-ps v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/superfly/flyctl v0.0.163
	golang.org/x/sys v0.0.0-20201013081832-0aaa2718063a // indirect
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
	google.golang.org/genproto v0.0.0-20200527145253-8367513e4ece // indirect
)

replace github.com/containerd/containerd => github.com/containerd/containerd v1.3.1-0.20200227195959-4d242818bf55

replace github.com/docker/docker => github.com/docker/docker v1.4.2-0.20200227233006-38f52c9fec82
