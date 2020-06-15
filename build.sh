#!/usr/bin/env bash

source env/env

# Make a build dir for docker
BUILD_DIR=dockerfile
mkdir ${BUILD_DIR}
cp requirements.txt Dockerfile ${BUILD_DIR}

# Build
docker build --network=host -t ${DOCKER_IMAGE} ${BUILD_DIR}

# Clean
rm -rf ${BUILD_DIR}