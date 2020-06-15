#!/usr/bin/env bash

source env/env

docker run --rm -it \
    -v $(pwd):/app \
    -w /app/handlers \
    --env-file ./env/env \
    --network=host \
    ${DOCKER_IMAGE} \
    bash # -c 'python test.py'