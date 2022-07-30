#!/usr/bin/env bash

docker run --rm -it -v "$(pwd):/docs" squidfunk/mkdocs-material:latest build
