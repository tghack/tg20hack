FROM ubuntu:bionic

RUN apt update && apt install -y python3 xinetd
RUN useradd -m -s /bin/bash tghack

COPY space_puzzle.py /home/tghack/space_puzzle.py
RUN chmod 765 /home/tghack/space_puzzle.py

COPY puzzles-bw.txt /home/tghack/puzzles-bw.txt
RUN chmod 644 /home/tghack/puzzles-bw.txt
COPY puzzles-color.txt /home/tghack/puzzles-color.txt
RUN chmod 644 /home/tghack/puzzles-color.txt
COPY puzzle-flag.txt /home/tghack/puzzle-flag.txt
RUN chmod 644 /home/tghack/puzzle-flag.txt

COPY space_puzzle.xinetd /etc/xinetd.d/space_puzzle
RUN chmod 644 /etc/xinetd.d/space_puzzle
RUN chown -R root:root /home/tghack

COPY wrap.sh /opt/wrap.sh
RUN chmod 755 /opt/wrap.sh

RUN chmod 1770 /tmp
RUN chown -R root:root /home/tghack

#ENTRYPOINT ["/bin/bash"]
CMD service xinetd start && /bin/bash
