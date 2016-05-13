import OpenSSL
import base64


def get_private_key(path):
    with open('server.key', 'r') as f:
        private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, f.read())
    return private_key


def get_public_key(path):
    with open('server.crt', 'r') as f:
        private_key = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
    return private_key


def sign(private_key, data, digest='sha256'):
    signature = OpenSSL.crypto.sign(private_key, data, digest)
    signature_base64 = base64.encodestring(signature)
    return signature_base64


def verify(public_key, signature, data, digest='sha256'):
    try:
        is_valid = OpenSSL.crypto.verify(public_key, signature, data, digest)
        return is_valid is None
    except OpenSSL.crypto.Error:
        return False


if __name__ == '__main__':
    data = 'Hello Crypto'

    # Sign data ('Hello Crypto') with private key
    signature = sign(get_private_key('server.key'), data)
    print('Signature:', signature)

    # Verify data/signature with public key
    signature_raw = base64.decodestring(signature)
    is_valid = verify(get_public_key('server.crt'), signature_raw, data)
    print('Is data ({}) valid: {}'.format(data, is_valid))

    # Try it with invalid data
    signature_raw = base64.decodestring(signature)
    is_valid = verify(get_public_key('server.crt'), signature_raw, data+'_bad')
    print('Is data ({}) valid: {}'.format(data+'_bad', is_valid))
