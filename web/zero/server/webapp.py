#!/usr/bin/env python3
import tornado.web
import secrets
import ctypes

with open("/hack/index.html") as index_file:
    index_html = index_file.read()
with open("/hack/password.txt") as password_file:
    app_password = password_file.read().strip()

flag = "TG20{strlen_is_bad_mkay}"
hashing = ctypes.CDLL("/hack/hash.so")

def create_hash(str):
    digest_buf = ctypes.create_string_buffer(130)
    password_buf = ctypes.create_string_buffer(bytes(str, 'utf-8'), 130)
    hashing.compute_hash(digest_buf, password_buf)
    return digest_buf.value

class MainHandler(tornado.web.RequestHandler):
    def post(self):
        password_hash = create_hash(self.get_body_argument('password', ''))
        if secrets.compare_digest(password_hash, create_hash(app_password)):
            self.write(flag)
        else:
            self.write(index_html)

    def get(self):
        self.write(index_html)

app = tornado.web.Application([(r"/", MainHandler)])
app.listen(4002)
tornado.ioloop.IOLoop.current().start()
