#!/usr/bin/env bash
# 交叉编译 pmail-hermes-push
# 用法: ./scripts/build.sh [arm64|amd64|all]
set -euo pipefail

export PATH=/usr/local/go/bin:$PATH
cd "$(dirname "$0")/.."

TARGET="${1:-all}"
GO_VERSION=$(go version | awk '{print $3}')

build() {
    local arch="$1"
    local out="pmail_hermes_push"
    if [ "$arch" != "$(go env GOARCH)" ]; then
        out="pmail_hermes_push_${arch}"
    fi
    echo "==> building linux/${arch} -> ${out}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -ldflags="-s -w" -o "${out}" .
}

case "${TARGET}" in
    arm64) build arm64 ;;
    amd64) build amd64 ;;
    all)
        build "$(go env GOARCH)"
        build amd64
        [ "$(go env GOARCH)" != "arm64" ] && build arm64
        ;;
    *) echo "unknown arch: ${TARGET}"; exit 1 ;;
esac

echo "done. (go ${GO_VERSION})"
