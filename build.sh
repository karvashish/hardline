#!/bin/sh

set -e

echo "== building hardline =="
go mod tidy
go build -o tmp/hardline cmd/hardline/main.go
