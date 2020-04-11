#!/usr/bin/env python3
import socket
import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.template
import tornado.escape
import binascii
import sys
import os

VSOCK_PORT = 2000
VSOCK_CID = 20

# TODO: Validate cookies from client

with open("/hack/main.html") as main_file:
    main_data = main_file.read()

with open("/hack/listing.html") as listing_file:
    listing_data = listing_file.read()

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        prefix = self.request.headers.get("Challenge-Instance", "")
        files = os.listdir("/uploads")
        
        listing_template = tornado.template.Template(listing_data.strip())
        listing_content = listing_template.generate(files=files, prefix=prefix)
        template_data = main_data.replace("file_listing", str(listing_content, sys.stdout.encoding))
        main_template = tornado.template.Template(template_data)
        content = main_template.generate(prefix=prefix)
        self.finish(content)

    def post(self):
        prefix = self.request.headers.get("Challenge-Instance", "")
        for files in self.request.files.values():
            for finfo in files:
                fname = tornado.escape.url_unescape(finfo.filename, plus=False)
                with open("/uploads/" + fname, "w+b") as f:
                    f.write(finfo.body)
        self.redirect("/" + prefix, status=303)

class PlainFileHandler(tornado.web.StaticFileHandler):
    def get_content_type(self):
        return 'text/plain;charset=UTF-8'

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/(.*)", PlainFileHandler, {"path": "/uploads"}),
    ])

if __name__ == "__main__":
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
    sock.bind((VSOCK_CID, VSOCK_PORT))
    sock.listen()
    app = make_app()
    server = tornado.httpserver.HTTPServer(app)
    server.add_socket(sock)
    tornado.ioloop.IOLoop.current().start()
