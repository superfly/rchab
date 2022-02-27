#!/bin/sh

set -eu

CPUS=$(nproc)
addgroup nixbld
for num in `seq 1 $CPUS`; do
  adduser --disabled-password nixbld${num} -G nixbld
done