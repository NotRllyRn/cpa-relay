SHELL := /bin/sh
export GOTOOLCHAIN := go1.26.10
export GOAMD64 := v1
export CGO_ENABLED := 1
export CGO_CFLAGS := -O2 -g -march=x86-64 -mtune=generic

.PHONY: test race vet build abi check clean

test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
build:
	@test "$$(go env GOHOSTOS)/$$(go env GOHOSTARCH)" = linux/amd64 || (echo 'Build on Linux amd64 with a compatible libc'; exit 1)
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -buildmode=c-shared -o dist/cpa-relay.so ./cmd/cpa-relay
	mkdir -p dist/docs/licenses
	cp THIRD_PARTY_NOTICES.md dist/
	cp docs/licenses/* dist/docs/licenses/
abi: build
	python3 tests/abi_smoke.py dist/cpa-relay.so
check: test race vet abi
clean:
	rm -rf dist
