FROM debian:buster-slim AS build

RUN ["mkdir", "/hack"]
COPY src /hack/src
RUN ["bash", "/hack/src/build-install.sh"]

FROM debian:buster-slim

COPY --from=build /hack /hack
RUN ["bash", "/hack/src/node-install.sh"]

USER hack
CMD ["/usr/bin/tini", "/hack/start"]
