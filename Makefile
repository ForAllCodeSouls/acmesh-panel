VERSION ?= 0.1.3
IMAGE   ?= acmesh-panel
BIN     := bin/acmesh-panel

.PHONY: all build test ui-test run image image-multi up up-build down fmt vet clean

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.appVersion=$(VERSION)" -o $(BIN) .

fmt:
	gofmt -w *.go

vet:
	go vet ./...

# 端到端测试：真实进程 + 假 acme.sh，覆盖认证/CSRF/限流/签发/私钥审计/路径穿越
test: vet
	@mkdir -p /tmp/build
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /tmp/build/acmesh-panel .
	python3 tests/e2e.py

ui-test:
	node tests/ui-check.js

# 本地开发：用 fake acme.sh，数据落在 .dev/（不入库）
run: build
	@mkdir -p .dev/acme .dev/data
	ACME_HOME=$(CURDIR)/.dev/acme \
	ACME_BIN=$(CURDIR)/tests/fake-acme.sh \
	ACME_PANEL_DATA=$(CURDIR)/.dev/data \
	ACME_PANEL_LISTEN=0.0.0.0:8800 \
	ACME_PANEL_PASSWORD=dev-password-123 \
	ACME_PANEL_CRON=0 \
	./$(BIN)

# 单架构镜像
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

# 多架构（amd64 + arm64）。需要 buildx；用 --push 推到仓库，或加 --load 只载入单架构
image-multi:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE):$(VERSION) --push .

# 用 GHCR 镜像启动
up:
	docker compose pull
	docker compose up -d

# 用当前目录源码构建镜像启动
up-build:
	docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build

down:
	docker compose down

clean:
	rm -rf bin .dev
