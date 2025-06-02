GO      := go
GOFLAGS += -race

build:
	@$(GO) build $(GOFLAGS) .
help:
	@sudo ./symbolon_core help
start:
	@sudo ./symbolon_core $(ARGS)
run: build
	@sudo ./symbolon_core run
