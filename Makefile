VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet dist clean install
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/portsentinel ./cmd/portsentinel
test:
	go test ./...
vet:
	go vet ./...
dist:
	rm -rf dist && mkdir dist
	for arch in amd64 arm64; do \
	  out=portsentinel_$(VERSION)_linux_$$arch; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$out/portsentinel ./cmd/portsentinel; \
	  cp -r README.md LICENSE CHANGELOG.md deploy examples dist/$$out/; \
	  tar -C dist -czf dist/$$out.tar.gz $$out && rm -rf dist/$$out; \
	done
	cd dist && sha256sum *.tar.gz > checksums.txt
install: build
	install -Dm755 bin/portsentinel /usr/local/bin/portsentinel
	install -Dm644 deploy/portsentinel.service /etc/systemd/system/portsentinel.service
	install -Dm644 deploy/portsentinel.timer /etc/systemd/system/portsentinel.timer
	install -d -m750 /etc/portsentinel /var/lib/portsentinel /var/log/portsentinel
	test -f /etc/portsentinel/config.yaml || install -m600 examples/config.yaml /etc/portsentinel/config.yaml
clean:
	rm -rf bin dist
