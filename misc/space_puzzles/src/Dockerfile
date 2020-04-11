FROM ubuntu:bionic

RUN apt update && apt install -y \
		build-essential \
		cmake \
		git \
		libpng-dev \
		pkg-config

WORKDIR /opt
RUN git clone https://github.com/Taywee/args.git
RUN cd args && make install
RUN git clone https://github.com/ImageMagick/ImageMagick.git
WORKDIR /opt/ImageMagick
RUN ./configure && make -j8 && make install

WORKDIR /opt
RUN apt install -y libspdlog-dev
RUN echo "export LD_LIBRARY_PATH=/usr/local/lib/" >> /root/.bashrc

RUN apt install -y \
		python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential \
		python3-numpy \
		netcat

RUN python3 -m pip install --upgrade pip && python3 -m pip install --upgrade git+https://github.com/Gallopsled/pwntools.git@dev

ENTRYPOINT ["/bin/bash"]
