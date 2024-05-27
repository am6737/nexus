# 防止命令行参数被误认为是目标
%:
	@:

.PHONY: dep
dep: ## Get the dependencies
	@go mod tidy

.PHONY: lint
lint: ## Lint Golang files
	@golint -set_exit_status ${PKG_LIST}

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: test
test: fmt vet## Run unittests
	@go test -short ./...

build: dep ## Build the binary file
	@go build -ldflags "-s -w" -o nxclient main.go
