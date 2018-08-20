.PHONY: all

VERSION?="0.3.0.0"
CI_REGISTRY_IMAGE?="scep"

OS ?= ${shell uname|tr 'A-Z' 'a-z'}

BUILD_CMD=CGO_ENABLED=0 \
	GOOS=${OS} \
	go build -o $@ -ldflags "-X main.version=${VERSION} -X main.revision=${shell git rev-parse --short HEAD}" ./$<


all: \
	build/${OS}/scepserver \
	build/${OS}/scepclient

vendor:
	which dep || go get -u github.com/golang/dep/cmd/dep
	dep ensure -v

build/${OS}/scepclient: cmd/scepclient vendor
	${BUILD_CMD}

build/${OS}/scepserver: cmd/scepserver vendor
	${BUILD_CMD}

clean:
	rm -rf build vendor

dockerbuild:
	docker run -v ${CURDIR}:/go/src/project -w /go/src/project --rm golang make

test: vendor
	go test -v ./...