
FROM ubuntu:bionic

RUN dpkg --add-architecture i386 && apt update && apt full-upgrade -y && apt install -y xinetd libc6-dev-i386 make gcc
RUN useradd -m -s /bin/bash tghack

COPY boofy.c /home/tghack/boofy.c
RUN chmod 644 /home/tghack/boofy.c

COPY makefile /home/tghack/makefile
RUN chmod 644 /home/tghack/makefile

COPY boofy.xinetd /etc/xinetd.d/boofy
RUN chmod 644 /etc/xinetd.d/boofy

COPY wrap.sh /opt/wrap.sh
RUN chmod 755 /opt/wrap.sh

RUN chmod 1770 /tmp


WORKDIR /home/tghack
RUN make

CMD service xinetd start && /bin/bash

