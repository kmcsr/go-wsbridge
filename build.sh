#!/bin/bash

cd $(dirname $0)

function _build(){
	f="${GOOS}-${GOARCH}-$1"
	[ "$GOOS" == 'windows' ] && f="${f}.exe"
	echo "==> Building '$f'..."
	CGO_ENABLED=0 go build\
	 -trimpath -gcflags "-trimpath=${GOPATH}" -asmflags "-trimpath=${GOPATH}" -ldflags "-w -s"\
	 -o "./.output/$f" "./$1/main.go"
	return $?
}

GOOS=linux   GOARCH=amd64 _build server || exit $?
GOOS=linux   GOARCH=amd64 _build client || exit $?
GOOS=darwin  GOARCH=amd64 _build server || exit $?
GOOS=darwin  GOARCH=amd64 _build client || exit $?
GOOS=windows GOARCH=amd64 _build server || exit $?
GOOS=windows GOARCH=amd64 _build client || exit $?

echo "==> Done"
