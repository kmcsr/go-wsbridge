# syntax=docker/dockerfile:1

FROM golang:1.17-alpine AS BUILD

COPY ./go.mod ./go.sum "/go/src/github.com/kmcsr/go-wsbridge/"
COPY ./client "/go/src/github.com/kmcsr/go-wsbridge/client"

RUN cd "/go/src/github.com/kmcsr/go-wsbridge" &&\
 go build -o "/go/bin/linux-amd64-client" "./client"

FROM alpine:latest

COPY --from=BUILD "/go/bin/linux-amd64-client" /px/linux-amd64-client

RUN echo -e '#!/bin/sh\ncd $(dirname $0)\nexec /px/linux-amd64-client' >/px/runner.sh &&\
 chmod +x /px/runner.sh

CMD exec /px/runner.sh
