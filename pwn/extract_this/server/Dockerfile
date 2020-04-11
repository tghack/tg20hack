FROM ubuntu:bionic

RUN apt update && apt full-upgrade -y && apt install -y python3 xinetd
RUN useradd -m -s /bin/bash tghack

COPY extract.py /home/tghack/extract.py

COPY extract.xinetd /etc/xinetd.d/extract
RUN chmod 664 /etc/xinetd.d/extract

COPY flag.txt /flag.txt
RUN chmod 444 /flag.txt

COPY wrap.sh /opt/wrap.sh
RUN chmod 755 /opt/wrap.sh

RUN chmod 1770 /tmp
RUN chown -R tghack:tghack /home/tghack

CMD service xinetd start && /bin/bash
