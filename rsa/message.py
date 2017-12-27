from hashlib import sha256 as hasher
import base64
import struct


def read_key(filename):
    with open(filename) as f:
        keydata = base64.b64decode(f.read().split(None)[1])

    parts = []
    while keydata:
        # read the length of the data
        dlen = struct.unpack('>I', keydata[:4])[0]

        # read in <length> bytes
        data, keydata = keydata[4:dlen + 4], keydata[4 + dlen:]

        parts.append(data)

    head, e, mod = parts
    assert head == b'ssh-rsa', 'Unsupported key format '
    return bytes_to_int(e), bytes_to_int(mod)


def bytes_to_int(bts):
    return int.from_bytes(bts, 'big')


def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')


def str_to_bytes(s):
    return str.encode(s, 'utf-8')


def str_to_int(s):
    return bytes_to_int(str_to_bytes(s))


def int_to_str(i):
    return bytes_to_str(int_to_bytes(i))


def bytes_to_str(b):
    return b.decode('utf-8')


def int_to_hex(i):
    return format(i, 'x')


def hex_to_int(h):
    return int(h, 16)


def bytes_to_hex(b):
    return b.hex()


def hex_to_bytes(h):
    return bytes.fromhex(h)


def str_to_hex(s):
    return bytes_to_hex(str_to_bytes(s))


def hex_to_str(h):
    return bytes_to_str(hex_to_bytes(h))


class Message:

    def __init__(self, bytes):
        self.msg = bytes

    @classmethod
    def from_int(cls, i):
        return cls(int_to_bytes(i))

    @classmethod
    def from_hex(cls, h):
        return cls(hex_to_bytes(h))

    @classmethod
    def from_str(cls, s, encoding='utf-8'):
        return cls(str.encode(s, encoding))

    @classmethod
    def from_binary(cls, b):
        return cls(int_to_bytes(int(b, 2)))

    def int(self):
        return bytes_to_int(self.msg)

    def str(self, encoding='utf-8'):
        return self.msg.decode(encoding)

    def hex(self):
        return bytes_to_hex(self.msg)

    def bin(self):
        return format(bytes_to_int(self.msg), 'b')

    def bytes(self):
        return self.msg

    def __repr__(self):
        return repr(self.msg)

    def __eq__(self, other):
        return self.msg == other.msg

    def hash(self):
        return hasher(self.msg).hexdigest()

    def encrypt(self, key):
        e, n = key
        encrypted = pow(self.int(), e, n)
        self.msg = int_to_bytes(encrypted)

    def decrypt(self, key):
        d, n = key
        decrypted = pow(self.int(), d, n)
        self.msg = int_to_bytes(decrypted)

    def sign(self, key):
        d, n = key
        signature = pow(self.int(), d, n)
        return Message.from_int(signature)

    def verify(self, signature, key):
        e, n = key
        message = pow(signature.int(), e, n)
        return self.msg == int_to_bytes(message)

