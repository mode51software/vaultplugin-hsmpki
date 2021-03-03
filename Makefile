GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o bin/plugins/vaultplugin-hsmpki cmd/vaultplugin-hsmpki/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin/plugins -log-level=debug

clean:
	rm -f ./bin/plugins/vaultplugin-hsmpki

#enable:
#	vault secrets enable -path=hsmpki vaultplugin-hsmpki

fmt:
	go fmt $$(go list ./...)

test:	hsmconnection

hsmconnection:
	go test -v -run TestConnectPkcs11Connection ./pkg/hsmpki

pathrolecreate:
	go test -v -run TestPathRoleCreate ./pkg/hsmpki

pathsetsignedintermediate:
	go test -v -run TestPathSetSignedIntermediate ./pkg/hsmpki

pathsetcrlconfig:
	go test -v -run TestPathSetCRLConfig ./pkg/hsmpki

pathfetchcrl:
	go test -v -run TestPathFetchCRL ./pkg/hsmpki

pathrevokecrl:
	go test -v -run TestPathRevokeCRL ./pkg/hsmpki

pathrotatecrl:
	go test -v -run TestPathRotateCRL ./pkg/hsmpki

pathtidycrl:
	go test -v -run TestPathTidyCRL ./pkg/hsmpki


.PHONY: build clean fmt start enable
