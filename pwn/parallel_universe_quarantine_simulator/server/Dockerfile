FROM ubuntu:bionic

RUN dpkg --add-architecture i386 && apt update && apt install -y build-essential clang-8 libc6-dev-i386
COPY src/ /opt/src/
WORKDIR /opt/src/
RUN make

FROM tghack/parallel
RUN dpkg --add-architecture i386 && apt update && apt install -y libc6-dev-i386
# delete some old files
RUN rm /home/tghack/banner.txt && rm /home/tghack/flag.txt && \
	rm /etc/xinetd.d/parallel && rm /home/tghack/run.sh && \
	rm /home/tghack/pwnme*
COPY server/parallel2.xinetd /etc/xinetd.d/parallel2
COPY server/run.sh /home/tghack/run.sh
COPY src/banner.txt home/tghack/banner.txt
COPY flag.txt /home/tghack
COPY --from=0 /opt/src/quarantine /home/tghack/
COPY --from=0 /opt/src/quarantine32 /home/tghack/

#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["xinetd", "-dontfork"]
