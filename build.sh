#!/bin/sh
#
# Build manually for pushing dev releases
#

REPO=flyio/rchab:$1
docker build --platform linux/amd64 --build-arg=$(git rev-parse HEAD) -t $REPO .
docker push $REPO
