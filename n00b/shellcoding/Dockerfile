FROM ubuntu:bionic

RUN apt update && apt install -y python3 python3-pip cmake git

WORKDIR /opt
RUN git clone https://github.com/keystone-engine/keystone.git
WORKDIR /opt/keystone
RUN mkdir build
WORKDIR /opt/keystone/build
RUN cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="X86" -G "Unix Makefiles" ..
RUN make -j8
RUN make install
RUN ldconfig

RUN pip3 install unicorn capstone keystone-engine
RUN apt install -y xinetd

COPY emu.py /opt/emu.py

COPY wrap.sh /opt/wrap.sh
COPY shellcoding.xinetd /etc/xinetd.d/shellcoding

WORKDIR /opt

RUN chmod +x /opt/emu.py

#ENTRYPOINT ["/bin/bash"]
CMD service xinetd start && /bin/bash
