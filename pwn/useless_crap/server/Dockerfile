FROM ubuntu:bionic

RUN apt update && apt install -y build-essential gawk python3 bison
COPY glibc-2.31 /opt/glibc-2.31/
RUN mkdir /opt/build
WORKDIR /opt/build
RUN ../glibc-2.31/configure --disable-sanity-checks
RUN make -j8 && make install

RUN useradd -m -s /bin/bash crap
COPY flag.txt /home/crap/flag.txt
RUN chmod 644 /home/crap/flag.txt

COPY server/run.sh /home/crap/run.sh
RUN chmod 555 /home/crap/run.sh

RUN apt install -y xinetd
COPY server/crap.xinetd /etc/xinetd.d/crap

RUN apt install -y libseccomp-dev
RUN cp /lib/x86_64-linux-gnu/libseccomp.so.2 /usr/local/lib/
RUN cp /lib/x86_64-linux-gnu/libseccomp.so.2.4.1 /usr/local/lib

COPY src/Makefile /opt/
COPY src/main.c /opt/
WORKDIR /opt
RUN make main
RUN mv /opt/main /home/crap/crap
#COPY main /home/crap/crap
RUN chmod 755 /home/crap/crap

#ENTRYPOINT ["/bin/bash"]
CMD service xinetd start && /bin/bash
