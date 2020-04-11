FROM ubuntu:bionic
RUN apt update && apt full-upgrade -y && \
    apt-get install -y --no-install-recommends binwalk exiftool zip binutils \
    python3-pip
RUN pip3 install setuptools && pip3 install stego-lsb 
ARG LC_ALL=C.UTF-8 
ARG LANG=C.UTF-8
COPY tghack/* /home/tghack/
RUN chmod 777 /home/tghack/

WORKDIR /home/tghack/

# create password protected zip for pikalang-part of flag
# hidden_pika.txt contains last part of flag.
# Hide in EXIF:UserComment. 
RUN zip -P $(cat pass.txt) hidden.zip hidden_pika.txt
RUN cat hidden.zip pass_hint.txt > hiddeny.zip
RUN exiftool -UserComment="$(base64 hiddeny.zip)" pika.png

# LSB-embedding message using stego-lsb: https://pypi.org/project/stego-lsb/
# embed password hint in growlithe image
RUN stegolsb steglsb -h -i growly.jpg -s pwd_hint.txt  -o growly.png
RUN cat growly.png lsbsteg_hint.txt > growlie.png 


RUN rm hidden.zip hiddeny.zip growly.png
# Concatenate files
RUN cat unown.png pika.png growlie.png > unowns.png

CMD /bin/bash
