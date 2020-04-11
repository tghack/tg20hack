FROM alpine:3.11 AS image
RUN ["apk", "add", "--no-cache", "openrc", "python3", "py3-tornado", "squashfs-tools", "musl"]
COPY ["image/setup.sh", "/setup.sh"]
COPY ["image/files", "/hack"]
RUN ["sh", "/setup.sh"]

FROM alpine:3.11 AS build
RUN ["mkdir", "-p", "/hack/firecracker"]
RUN ["apk", "add", "--no-cache", "go", "musl-dev", "curl", "git"]
RUN ["apk", "upgrade", "--no-cache"]

COPY ["src", "/hack/src"]
RUN ["sh", "/hack/src/install.sh"]

FROM alpine:3.11
RUN ["apk", "add", "--no-cache", "musl"]
RUN ["apk", "upgrade", "--no-cache"]

COPY --from=build /hack /hack
COPY --from=image /image.squash /hack/firecracker/rootfs.img
RUN ["chown", "-R", "1000:1000", "/hack"]

USER 1000:1000
ENTRYPOINT ["/hack/start"]
