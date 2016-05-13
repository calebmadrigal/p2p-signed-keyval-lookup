import socket
import ssl
import threading
import time
import random
import msgpack


class DistKeyLookupClient:
    def __init__(self, server_host, server_port, cache_timeout=300, server_cert="server.crt"):
        self.server_url= server_host
        self.server_port= server_port
        self.cache_timeout = cache_timeout
        self.server_cert = server_cert
        self.peer_list = []
        self.local_db = {}
        self.my_ip = None
        self.my_port = None

        self.start_peer_server()
        self.make_server_request('register')

    def make_server_request(self, command, arg=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Require a certificate from the server. We used a self-signed certificate
        # so here ca_certs must be the server certificate itself.
        ssl_sock = ssl.wrap_socket(s,
                                   ca_certs=self.server_cert,
                                   cert_reqs=ssl.CERT_REQUIRED)

        ssl_sock.connect((self.server_url, self.server_port))

        if command == 'register':
            self.my_ip = ssl_sock.getsockname()[0]
            arg = (self.my_ip, self.my_port)
            print('My ip: {}, my port: {}'.format(self.my_ip, self.my_port))

        req = msgpack.dumps((command, arg))
        ssl_sock.write(req)

        resp_raw = ssl_sock.recv(100000)
        success, resp = msgpack.loads(resp_raw)

        print('Success: {}, Response from server: {}'.format(success, resp))
        return success, resp

    def make_peer_request(self, peer, command, arg=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(peer)
            req = msgpack.dumps((command, arg))
            s.send(req)
            resp_raw = s.recv(100000)
            success, resp = msgpack.loads(resp_raw)
            print('Peer Success: {}, Response from peer: {}'.format(success, resp))
            return success, resp
        except ConnectionRefusedError:
            return False, None

    def get_peers(self):
        try:
            success, peer_list = self.make_server_request('get_peer_list')
            if success:
                self.peer_list = peer_list
        except ConnectionRefusedError:
            # Just fall back to the old local peer_list
            pass
        return self.peer_list

    def get_random_peer(self):
        peer_list_minus_self = set([tuple(i) for i in self.peer_list]) - set([(self.my_ip.encode(), self.my_port)])
        if peer_list_minus_self:
            return random.sample(peer_list_minus_self, 1)[0]
        else:
            return None

    def get_key(self, key):
        # To make it easier to test peer requests, temporarily comment out the self requests
        #if key in self.local_db:
        #    timestamp, value = self.local_db[key]
        #    if time.time() - timestamp <= self.cache_timeout:
        #        print('Got value from local cache: {}'.format(value))
        #        return value

        peer = self.get_random_peer()
        if peer is not None:
            peer = (peer[0].decode(), peer[1])
            print('Making peer request to: {}'.format(peer))
            success, resp = self.make_peer_request(peer, 'get', key)
            if success:
                print('Got value from peer ({}): {}'.format(peer, resp))

                timestamp = time.time()
                # Don't update the timestamp (if it exists) based on the peer request
                if key in self.local_db:
                    timestamp = self.local_db[key][0]
                self.local_db[key] = (timestamp, resp)

                return resp

        try:
            success, resp = self.make_server_request('get', key)
            if success:
                print('Got value from server: {}'.format(resp))
                self.local_db[key] = (time.time(), resp)
                return resp
        except ConnectionRefusedError:
            pass

        return None

    def handle_peer(self, sock, addr):
        print('\tGot peer connection from {}'.format(addr))

        req_raw = sock.recv(100000)
        (command, arg) = msgpack.loads(req_raw)

        if command == b'get':
            key = arg.decode()
            if key in self.local_db:
                (val_timestamp, val) = self.local_db[key]
                if time.time() - val_timestamp < self.cache_timeout:
                    result = (True, val)
                else:
                    self.local_db.pop(key)
                    result = (False, None)
            else:
                result = (False, None)
        elif command == b'get_peer_list':
            result = (True, self.peer_list)
        else:
            result = (False, None)

        sock.sendall(msgpack.dumps(result))

    def peer_server_thread(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))
        self.my_port = s.getsockname()[1]
        s.listen(16)
        while True:
            c, a = s.accept()
            try:
                self.handle_peer(c, a)
            finally:
                c.close()
            
    def start_peer_server(self):
        t = threading.Thread(target=self.peer_server_thread)
        t.start()


if __name__ == '__main__':
    client = DistKeyLookupClient('127.0.0.1', 1337, cache_timeout=60)
    while True:
        print('c =', client.get_key('c'))
        client.get_peers()
        time.sleep(5)

