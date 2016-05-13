# p2p-signed-keyval-lookup

Peer-to-peer signed distributed key/value lookup.

This is a key/value lookup server which can cache key/values on its clients, which can then be queried by their peers for the value of various keys. But we don't trust the peers - we only trust the server. So when the value of a key is requested, both its value and signature (signed by the server) are returned. If a peer request is made, that signature is checked against the server's certificate (which would be shipped along with the client) to ensure it is indeed correct.

The values on the peers have an expiration which, when reached, causes the lookup to be done on the server again.

## Usage

Create public/private keypair (`server.crt` and `server.key`):

    ./create_keys.sh

Install dependencies - pyOpenSSL and msgpack:

    pip3 install -r requirements.txt

Run the server:

    python3 p2p_keyval_server.py

Run some clients (do this for each client you want to run):

    python3 p2p_keyval_client.py

