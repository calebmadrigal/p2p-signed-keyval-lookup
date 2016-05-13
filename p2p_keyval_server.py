import time
import socket
import ssl
import base64
import msgpack
import OpenSSL


def get_private_key(private_key_path):
    with open(private_key_path, 'r') as f:
        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, f.read())
    return private_key


class DistKeyValServer:
    def __init__(self, host='', port=1337, server_cert='server.crt', server_key='server.key'):
        self.server_host = host
        self.server_port = port
        self.server_cert = server_cert
        self.server_key = server_key
        self.server_key_data = get_private_key(server_key)

        # key -> (val, signature)
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
        try:
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
        finally:
            bindsocket.close()

    def sign(self, data, digest='sha256'):
        signature = OpenSSL.crypto.sign(self.server_key_data, data, digest)
        signature_base64 = base64.encodestring(signature)
        return signature_base64

    def set_key(self, key, val):
        val_signature = self.sign(val)
        self.db[key] = (val, val_signature)





if __name__ == '__main__':
    server = DistKeyValServer()
    server.set_key('a', '1')
    server.set_key('b', '2')
    server.set_key('c', '0')
    server.set_key('d', '4')
    server.set_key('e', '5')

    def test_value_update_thread():
        for i in range(100000):
            server.set_key('c', str(i))
            if i%10 == 0:
                print('c =', i)
            time.sleep(1)

    import threading
    t = threading.Thread(target=test_value_update_thread)
    t.start()

    server.serve()
