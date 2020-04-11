#!/usr/bin/env python3
import socket
import tornado.ioloop
import tornado.web
import tornado.httpserver

VSOCK_PORT = 2000
VSOCK_CID = 20

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        with open('/uploads/cookies.txt', 'a+') as f:
            f.write(str(self.request.headers))
        with open('/uploads/cookies.txt', 'r') as f:
            self.finish(f.read())

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
    sock.bind((VSOCK_CID, VSOCK_PORT))
    sock.listen()
    app = make_app()
    server = tornado.httpserver.HTTPServer(app)
    server.add_socket(sock)
    tornado.ioloop.IOLoop.current().start()
