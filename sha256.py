import struct

__all__ = ['SHA256', 'sha256', 'MD5', 'md5']

# -------------------- SHA256 --------------------
class SHA256:
    _K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        self._H = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self._unprocessed = b''
        self._message_byte_length = 0

    @staticmethod
    def _right_rotate(value, shift):
        return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF

    def update(self, arg):
        if not isinstance(arg, (bytes, bytearray, memoryview)):
            raise TypeError("data must be a bytes-like object")
        data = bytes(arg)
        self._message_byte_length += len(data)
        data = self._unprocessed + data
        chunk_count = len(data) // 64
        for i in range(chunk_count):
            self._process_chunk(data[i*64:(i+1)*64])
        self._unprocessed = data[chunk_count*64:]
        return self

    def _process_chunk(self, chunk):
        w = list(struct.unpack('>16L', chunk))
        for i in range(16, 64):
            s0 = (self._right_rotate(w[i-15], 7) ^ self._right_rotate(w[i-15], 18) ^ (w[i-15] >> 3))
            s1 = (self._right_rotate(w[i-2], 17) ^ self._right_rotate(w[i-2], 19) ^ (w[i-2] >> 10))
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = self._H
        for i in range(64):
            S1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + self._K[i] + w[i]) & 0xFFFFFFFF
            S0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        self._H = [
            (self._H[0] + a) & 0xFFFFFFFF,
            (self._H[1] + b) & 0xFFFFFFFF,
            (self._H[2] + c) & 0xFFFFFFFF,
            (self._H[3] + d) & 0xFFFFFFFF,
            (self._H[4] + e) & 0xFFFFFFFF,
            (self._H[5] + f) & 0xFFFFFFFF,
            (self._H[6] + g) & 0xFFFFFFFF,
            (self._H[7] + h) & 0xFFFFFFFF
        ]

    def digest(self):
        clone = self.copy()
        length = clone._message_byte_length
        clone._unprocessed += b'\x80'
        clone._unprocessed += b'\x00' * ((56 - (length + 1) % 64) % 64)
        clone._unprocessed += struct.pack('>Q', length * 8)
        for i in range(0, len(clone._unprocessed), 64):
            clone._process_chunk(clone._unprocessed[i:i+64])
        return b''.join(h.to_bytes(4, 'big') for h in clone._H)

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        new = self.__class__()
        new._H = self._H[:]
        new._unprocessed = self._unprocessed[:]
        new._message_byte_length = self._message_byte_length
        return new

def sha256(data=b''):
    h = SHA256()
    if data:
        h.update(data)
    return h

# -------------------- MD5 --------------------
class MD5:
    _s = [7,12,17,22]*4 + [5,9,14,20]*4 + [4,11,16,23]*4 + [6,10,15,21]*4
    _K = [int(abs(__import__('math').sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    def __init__(self):
        self._a0 = 0x67452301
        self._b0 = 0xefcdab89
        self._c0 = 0x98badcfe
        self._d0 = 0x10325476
        self._unprocessed = b''
        self._message_byte_length = 0

    def update(self, arg):
        if not isinstance(arg, (bytes, bytearray, memoryview)):
            raise TypeError("data must be a bytes-like object")
        data = self._unprocessed + bytes(arg)
        self._message_byte_length += len(arg)
        chunk_count = len(data) // 64
        for i in range(chunk_count):
            self._process_chunk(data[i*64:(i+1)*64])
        self._unprocessed = data[chunk_count*64:]
        return self

    def _process_chunk(self, chunk):
        M = list(struct.unpack('<16I', chunk))
        a, b, c, d = self._a0, self._b0, self._c0, self._d0
        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3*i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7*i) % 16

            temp = (a + f + self._K[i] + M[g]) & 0xFFFFFFFF
            rotated = ((temp << self._s[i]) | (temp >> (32 - self._s[i]))) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + rotated) & 0xFFFFFFFF

        self._a0 = (self._a0 + a) & 0xFFFFFFFF
        self._b0 = (self._b0 + b) & 0xFFFFFFFF
        self._c0 = (self._c0 + c) & 0xFFFFFFFF
        self._d0 = (self._d0 + d) & 0xFFFFFFFF

    def digest(self):
        clone = self.copy()
        message = clone._unprocessed
        message_len_bits = clone._message_byte_length * 8
        message += b'\x80'
        message += b'\x00' * ((56 - (len(message) % 64)) % 64)
        message += struct.pack('<Q', message_len_bits)
        for i in range(0, len(message), 64):
            clone._process_chunk(message[i:i+64])
        return struct.pack('<4I', clone._a0, clone._b0, clone._c0, clone._d0)

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        new = MD5()
        new._a0 = self._a0
        new._b0 = self._b0
        new._c0 = self._c0
        new._d0 = self._d0
        new._unprocessed = self._unprocessed[:]
        new._message_byte_length = self._message_byte_length
        return new

def md5(data=b''):
    h = MD5()
    if data:
        h.update(data)
    return h