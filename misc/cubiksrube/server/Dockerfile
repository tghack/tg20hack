FROM ubuntu:bionic

RUN apt update && apt full-upgrade -y && apt install -y xinetd python3 python3-numpy
RUN useradd -m -s /bin/bash tghack

COPY server.py /home/tghack/server.py
COPY rubik.py /home/tghack/rubik.py
RUN chmod 755 /home/tghack/server.py /home/tghack/rubik.py

COPY server.xinetd /etc/xinetd.d/server
RUN chmod 644 /etc/xinetd.d/server

COPY wrap.sh /opt/wrap.sh
RUN chmod 755 /opt/wrap.sh

RUN chmod 1770 /tmp
RUN chown -R root:root /home/tghack

CMD service xinetd start && /bin/bash
