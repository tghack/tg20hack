FROM alpine:edge as build

RUN ["apk", "add", "--no-cache", "go", "sqlite", "git", "gcc", "libc-dev"]
COPY src /src

ENV GOPATH=/go
WORKDIR /src
RUN ["mkdir", "-p", "/go"]
RUN ["go", "get", "github.com/mattn/go-sqlite3"]
RUN ["go", "build", "-o", "/server", "."]

FROM alpine:edge
RUN ["apk", "add", "--no-cache", "sqlite"]
RUN ["mkdir", "-p", "/server/db"]

COPY --from=build /server /server/start
COPY html /server/html
ENTRYPOINT ["/server/start"]
