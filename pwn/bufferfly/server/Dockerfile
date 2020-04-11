FROM ubuntu:bionic

RUN dpkg --add-architecture i386 && apt update && apt full-upgrade -y && apt install -y xinetd libc6-dev-i386 make gcc
RUN useradd -m -s /bin/bash tghack

COPY bufferfly.c /home/tghack/bufferfly.c
RUN chmod 644 /home/tghack/bufferfly.c

COPY makefile /home/tghack/makefile
RUN chmod 644 /home/tghack/makefile

COPY bufferfly.xinetd /etc/xinetd.d/bufferfly
RUN chmod 644 /etc/xinetd.d/bufferfly

COPY flag.txt /home/tghack/flag.txt
RUN chmod 644 /home/tghack/flag.txt

COPY wrap.sh /opt/wrap.sh
RUN chmod 755 /opt/wrap.sh

RUN chmod 1770 /tmp
RUN chown -R root:root /home/tghack

WORKDIR /home/tghack
RUN make

ENTRYPOINT ["xinetd", "-dontfork"]
