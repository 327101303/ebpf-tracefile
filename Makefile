SRC = $(shell find . -type f -name '*.go' ! -name '*_test.go' )
ebpfProgramBase64 = $(shell base64 -w 0 ctrace/bpf/ctrace.bpf.c)

.PHONY: build
build: tar/ctrace

tar/ctrace: $(SRC) ctrace/bpf/ctrace.bpf.c
	GOOS=linux go build -v -o tar/ctrace -ldflags "-X ctrace/ctrace.ebpfProgramBase64Injected=$(ebpfProgramBase64)"

.PHONY: build-docker
build-docker: clean
	img=$$(docker build --target builder -q  .) && \
	cnt=$$(docker create $$img) && \
	docker cp $$cnt:/ctrace/tar - | tar -xf - ; \
	docker rm $$cnt ; docker rmi $$img



.PHONY: test
test:
	go test -v ./...

.PHONY: clean
clean:
	rm -rf tar || true

imageName ?= ctrace
.PHONY: docker
docker:
	docker build -t $(imageName) .

.PHONY: release
# release by default will not publish. run with `publish=1` to publish
goreleaserFlags = --skip-publish --snapshot
ifdef publish
	goreleaserFlags =
endif
release:
	EBPFPROGRAM_BASE64=$(ebpfProgramBase64) goreleaser release --rm-dist $(goreleaserFlags)
