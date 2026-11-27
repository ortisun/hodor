"""What a workload of the demonstration of Milestone 11 does, run in its own pod.

The demonstration sends this file to `python3 -` in a pod, with one JSON
document as its argument, and reads one JSON document back on the standard
output. It runs where the workload is, so that a request leaves from the
pod's own address and through the pod's own proxy, if it has one. It uses
nothing outside the standard library.

    {"do": "request", "method": "GET", "url": "...", "headers": {...}, "json": {...}, "form": {...}}
    {"do": "sign_in", "server": "...", "tenant": "...", "identifier": "...", "password": "...", "headers": {...}}
    {"do": "fail_until_locked_out", "server": "...", "tenant": "...", "most": 80, "headers": {...}}

`resolve` maps a host name to the address to connect to instead, as a
name the cluster's name service does not know is reached at a gateway;
`authority` is the certificate, in PEM, that a gateway's certificate is
checked against.
"""

import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def opener(document):
    resolve = document.get("resolve") or {}
    if resolve:
        original = socket.getaddrinfo

        def getaddrinfo(host, *rest, **named):
            return original(resolve.get(host, host), *rest, **named)

        socket.getaddrinfo = getaddrinfo
    handlers = [NoRedirects()]
    if document.get("authority"):
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(
            cadata=document["authority"])))
    return urllib.request.build_opener(*handlers)


def call(open_, method, url, headers=None, json_body=None, form=None):
    headers = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with open_.open(request, timeout=30) as response:
            return response.status, response.headers, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read().decode()


class Browser:
    """Keeps the cookies Hodor sets and the token against forged requests,
    as the demonstration's own browser does (deploy/demo/demo.py)."""

    def __init__(self, open_, server, headers):
        self.open = open_
        self.server = server
        self.headers = headers
        self.cookies = {}
        self.csrf_token = None

    def call(self, method, path, body=None):
        headers = dict(self.headers)
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        if self.csrf_token and method != "GET":
            headers["X-CSRF-Token"] = self.csrf_token
        status, answered, text = call(self.open, method, self.server + path, headers, body)
        for cookie in answered.get_all("Set-Cookie") or []:
            name, _, value = cookie.split(";")[0].partition("=")
            if "Max-Age=0" in cookie:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        try:
            body = json.loads(text) if text else {}
        except ValueError:
            body = {}
        if isinstance(body, dict) and body.get("csrf_token"):
            self.csrf_token = body["csrf_token"]
        return status, body

    def sign_in(self, tenant, identifier, password):
        base = f"/t/{tenant}/interaction/sign-in"
        status, body = self.call("POST", base)
        if status != 201:
            return status, body
        status, body = self.call("POST", f"{base}/steps/identifier", {"identifier": identifier})
        if status != 200:
            return status, body
        return self.call("POST", f"{base}/steps/password", {"password": password})


def main():
    document = json.loads(sys.argv[1])
    open_ = opener(document)
    headers = document.get("headers") or {}
    if document["do"] == "request":
        status, answered, text = call(open_, document.get("method", "GET"), document["url"], headers,
                                      document.get("json"), document.get("form"))
        said = {"status": status, "headers": {name.lower(): value for name, value in answered.items()},
                "text": text}
    elif document["do"] == "sign_in":
        browser = Browser(open_, document["server"], headers)
        status, body = browser.sign_in(document["tenant"], document["identifier"], document["password"])
        said = {"status": status, "body": body}
    elif document["do"] == "fail_until_locked_out":
        # Each attempt names another identifier, so that no identifier is
        # locked out: only the address the attempts come from can be.
        said = {"attempts": None}
        for attempt in range(1, document.get("most", 80) + 1):
            browser = Browser(open_, document["server"], headers)
            status, body = browser.sign_in(document["tenant"], f"nobody{attempt}@example.com", "a wrong guess")
            if status == 429:
                said = {"attempts": attempt, "code": body.get("code")}
                break
            if status != 200 or body.get("status") != "rejected":
                said = {"attempts": None, "unexpected": {"attempt": attempt, "status": status, "body": body}}
                break
    else:
        raise SystemExit(f"nothing to do: {document['do']}")
    print(json.dumps(said))


if __name__ == "__main__":
    main()
