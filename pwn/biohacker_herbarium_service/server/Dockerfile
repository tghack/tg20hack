FROM ubuntu:bionic

RUN apt update && apt install -y xinetd

RUN useradd -m -s /bin/bash tghack

COPY ./flag.txt /home/tghack/flag.txt
COPY server/plants.xinetd /etc/xinetd.d/plants
COPY uploads/chall /home/tghack
COPY server/wrap.sh /home/tghack

# just in case
RUN chmod 1770 /tmp
RUN chown -R root:root /home/tghack

ENTRYPOINT ["xinetd", "-dontfork"]
