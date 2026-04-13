SHELL := /bin/bash

VPS ?= livsho-ir

default: build

format: main.go
	goimports -w .

build: format
	go build -ldflags '-s -w' -o bin/smp

