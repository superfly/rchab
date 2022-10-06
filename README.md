# Remote controlled Hot Air Balloon

A Docker proxy for running Docker builds within Fly's infrastructure.

This is deployed as an independent Fly application when running `flyctl deploy --remote-only` for the first time.
Then, flyctl will use this remote builder for all applications deployed by the organization.

## Local dev

You probably/definitely want to use a separate vm, like vagrant. This service runs and manages its own docker service, which will maybe interfere with up the docker service on your system.

```shell
vagrant up     # gets you a vm with all the tools you need
vagrant ssh    # gets you onto that vm

cd rchab       # this is a folder on the vm, which is synced with the local repo and it support live updated 🎉

make run-local # run the service!
```

If that all worked, the service is running 🚀

http://localhost:8080 will have the rchab api in the vm and on your host.

## Testing with flyctl

`flyctl` can be configured to use a locally running version of rchap with:

```shell
FLY_REMOTE_BUILDER_HOST_WG=1 FLY_RCHAP_OVERRIDE_HOST=tcp://127.0.0.1:2375 LOG_LEVEL=debug fly deploy --remote-only
```

* `FLY_REMOTE_BUILDER_HOST_WG` disables usermode wireguard
* `FLY_RCHAP_OVERRIDE_HOST` indicates the ip and port for the docker client to connect to, which will be used instead of the remote builder machine 6pn ip
