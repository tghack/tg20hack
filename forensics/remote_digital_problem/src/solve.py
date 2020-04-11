#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import binascii

def out_to_bin(filename, out):
    with open(filename, "wb") as f:
        f.write(binascii.unhexlify(out))

def main():
    rdp_file = b""
    archive = "secret.7z"
    password = "computersarefun"
    pcap_file = "../uploads/capture.pcap"
    certificate = "win.pem"

    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        if len(sys.argv) > 2:
            certificate = sys.argv[2]

    print(f"[*] Decrypting and extracting packets from '{pcap_file}' using '{certificate}'...")
    out = subprocess.check_output(f"tshark -r '{pcap_file}' -q -o 'tls.keys_list:,3389,tpkt,{certificate}' -T fields -e 'rdp.virtualChannelData'", 
                                  shell=True)
    
    outs = out.split("\n".encode())
    outs = [out for out in outs if len(out) != 0]

    for i, out in enumerate(outs):
        # 88 is the first packet that includes the 7z file.
        if i == 88:
            # Strip off some junk before the actual 7z file
            out = out[24:]
    
        # The 7z file is split into these three packets in the pcap file.
        # (using the rdp.virtualChannelData filter)
        if i in (88, 89, 90):
            rdp_file += out.strip(b"\t")

    print(f"[*] Writing encrypted archive file '{archive}'")
    out_to_bin(archive, rdp_file)

    print(f"[+] Extracting '{archive}' using password '{password}'")
    subprocess.check_output(f"7z x -p{password} {archive}", shell=True)

if __name__ == '__main__':
    main()
