FROM alpine:3.11 as build
WORKDIR /hack

RUN ["apk", "add", "--no-cache", "build-base", "nettle", "nettle-dev"]
RUN ["apk", "upgrade", "--no-cache"]

COPY ["hash.c", "/hack/hash.c"]
COPY ["Makefile", "/hack/Makefile"]
RUN ["make"]

FROM alpine:3.11
WORKDIR /hack
RUN ["apk", "add", "--no-cache", "python3", "py3-tornado", "nettle"]
RUN ["apk", "upgrade", "--no-cache"]

COPY ["webapp.py", "/hack/webapp.py"]
COPY ["password.py", "/hack/password.py"]
COPY ["index.html", "/hack/index.html"]
COPY --from=build ["/hack/hash.so", "/hack/hash.so"]
RUN ["python3", "/hack/password.py"]

USER 1000:1000
ENTRYPOINT ["python3", "webapp.py"]
