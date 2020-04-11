#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import binascii

# Remember to create the folder "tmps" before running this script
def out_to_bin(i, out):
    with open("tmps/{}".format(i), "wb") as f:
        f.write(binascii.unhexlify(out))

out = subprocess.check_output("tshark -r ../uploads/capture.pcap -q -o 'tls.keys_list:,3389,tpkt,win.pem' -T fields -e 'rdp.virtualChannelData'", shell=True)
outs = out.split("\n".encode("utf-8"))
outs = [out for out in outs if len(out) != 0]

for i, out in enumerate(outs):
    out_to_bin(i, out.strip(b"\t"))
