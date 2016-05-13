import time
import socket
import ssl
import msgpack


class DistKeyLookupServer:
    def __init__(self, host='', port=1337, server_cert='server.crt', server_key='server.key'):
        self.server_host = host
        self.server_port = port
        self.server_cert = server_cert
        self.server_key = server_key

        # Key/value db
        self.db = {}

        # [(ip, port), (ip, port), ...]
        self.peer_list = set()

    def handle_client(self, connstream, client_addr):
        req_raw = connstream.read()
        (command, arg) = msgpack.loads(req_raw)
        print('Request from {}: Command: {}, Arg: {}'.format(client_addr, command, arg))

        if command == b'get':
            key = arg.decode()
            if key in self.db:
                result = (True, self.db[key])
            else:
                result = (False, None)
        elif command == b'register':
            peer_ip_port = tuple([arg[0].decode(), arg[1]])
            self.peer_list.add(peer_ip_port)
            result = (True, None)
        elif command == b'get_peer_list':
            result = (True, list(self.peer_list))
        else:
            result = (False, None)

        connstream.sendall(msgpack.dumps(result))

    def serve(self):
        bindsocket = socket.socket()
        bindsocket.bind((self.server_host, self.server_port))
        bindsocket.listen(16)
        print('Serving on {}:{}'.format(self.server_host, self.server_port))

        while True:
            client_sock, client_addr = bindsocket.accept()
            connstream = ssl.wrap_socket(client_sock,
                                         server_side=True,
                                         certfile=self.server_cert,
                                         keyfile=self.server_key)
            try:
                self.handle_client(connstream, client_addr)
            finally:
                connstream.shutdown(socket.SHUT_RDWR)
                connstream.close()


if __name__ == '__main__':
    server = DistKeyLookupServer()
    server.db['a'] = 1
    server.db['b'] = 2
    server.db['c'] = 3
    server.db['d'] = 4
    server.db['e'] = 5
    server.serve()

