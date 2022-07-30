#!/usr/bin/env bash

docker run --rm -it -p '127.0.0.1:8000:8000' -v "$(pwd):/docs:ro" squidfunk/mkdocs-material:latest