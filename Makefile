mkfile_path := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
build_path  := $(mkfile_path)build/
app_name    := open-go-dig
version     := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "develop")
ldflags     := -s -w -X 'main.version=$(version)'

.DEFAULT_GOAL := help
test_port   := 8099

.PHONY: help debug release clean-build build-linux build-darwin build-windows test-dns

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

debug: clean-build ## Build a debug version
	@mkdir -p $(build_path)
	@go build -o $(build_path)$(app_name) .
	@echo "Debug build done"

release: clean-build build-linux build-darwin build-windows ## Build the release version
	@echo "Release $(version) done"

clean-build: ## Clean the build directory
	@rm -fr $(build_path)

test-dns: debug ## Build, launch the server and run the DNS test battery
	@echo "Starting $(app_name) on port $(test_port)..."
	@OGD_PORT=$(test_port) $(build_path)$(app_name) >/dev/null 2>&1 & \
		srv_pid=$$!; \
		trap 'kill $$srv_pid 2>/dev/null' EXIT; \
		sleep 1.5; \
		$(mkfile_path)scripts/test-dns.sh http://localhost:$(test_port)

build-linux: ## Build release for GNU/Linux
	@mkdir -p $(build_path)
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-linux-amd64 .
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-linux-arm64 .
	@CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-linux-386 .

build-darwin: ## Build release for macOS
	@mkdir -p $(build_path)
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-darwin-amd64 .
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-darwin-arm64 .

build-windows: ## Build release for Windows
	@mkdir -p $(build_path)
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-windows-amd64.exe .
	@CGO_ENABLED=0 GOOS=windows GOARCH=386   go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-windows-386.exe .
