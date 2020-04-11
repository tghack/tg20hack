FROM alpine:latest AS build
RUN ["mkdir", "/hack"]
RUN ["apk", "add", "--no-cache", "go", "musl-dev"]
COPY src /hack/src

RUN ["go", "build", "-o", "/hack/start", "/hack/src/main.go", "/hack/src/storage.go", "/hack/src/products.go"]
RUN ["rm", "-f", "/hack/src/storage.go", "/hack/src/main.go", "/hack/src/products.go"]

FROM alpine:latest
RUN ["apk", "add", "--no-cache", "musl"]
COPY --from=build /hack /hack
USER 1000
CMD ["/hack/start"]
