# EdgeX Foundry Security Public Key Infrastructure (PKI) Init Service
[![license](https://img.shields.io/badge/license-Apache%20v2.0-blue.svg)](LICENSE)

## Introduction

This is an implemention of the module PKI-init to initialize the PKI related materials like CA certificates, TLS certificates, and private keys for the secure secret store to protect keys, certificates and other sensitive assets for the EdgeX Foundry project. Please refer to [Security Secret Store Chapter](https://docs.edgexfoundry.org/Ch-SecretStore.html) for a detailed documentation.

## Build

For running in Docker, please build the binaries and docker images before run `docker-compose up` on the existing file `docker-compose.yml`.  To build it, run the followings:

1. In the base directory, run `make build`
2. In the base directory, run `make docker`


## Run Docker

On the command line console, run `docker-compose up --build` from the directory `pkiinit` to start the whole Docker container stack.
