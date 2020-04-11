FROM ubuntu:bionic

RUN dpkg --add-architecture i386 && apt update && apt install -y build-essential clang-8 libc6-dev-i386
COPY src/ /opt/src/
WORKDIR /opt/src/
RUN make

FROM ubuntu:bionic
RUN apt update && apt install -y xinetd
RUN useradd -m -s /bin/bash tghack
COPY --from=0 /opt/src/dist /home/tghack/
# uncomment for debugging
#COPY --from=0 /opt/src/main /home/tghack/dist
COPY --from=0 /opt/src/pwnme64 /home/tghack/pwnme64
COPY --from=0 /opt/src/pwnme32 /home/tghack/pwnme32
COPY server/parallel.xinetd /etc/xinetd.d/parallel
COPY server/run.sh /home/tghack/run.sh
COPY src/banner.txt /home/tghack/banner.txt
COPY flag.txt /home/tghack/
RUN chmod 755 /home/tghack/dist

#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["xinetd", "-dontfork"]
