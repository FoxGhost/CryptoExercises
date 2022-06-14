
import struct

class SHA1Hash:

    def __init__(self, data):
        """
        Inititates the variables data and h. h is a list of 5 8-digit Hexadecimal
        numbers corresponding to
        (1732584193, 4023233417, 2562383102, 271733878, 3285377520)
        respectively. We will start with this as a message digest. 0x is how you write
        Hexadecimal numbers in Python
        """
        self.data = data

        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    @staticmethod
    def rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def padding(self):
        """
        Pads the input message with zeros so that padded_data has 64 bytes or 512 bits
        """
        padding = b"\x80" + b"\x00" * (63 - (len(self.data) + 8) % 64)
        padded_data = self.data + padding + struct.pack(">Q", 8 * len(self.data))
        return padded_data

    def split_blocks(self):
        """
        Returns a list of bytestrings each of length 64
        """
        return [
            self.padded_data[i : i + 64] for i in range(0, len(self.padded_data), 64)
        ]

    # @staticmethod
    def expand_block(self, block):
        """
        Takes a bytestring-block of length 64, unpacks it to a list of integers and
        returns a list of 80 integers after some bit operations
        """
        w = list(struct.unpack(">16L", block)) + [0] * 64
        for i in range(16, 80):
            w[i] = self.rotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
        return w

    def final_hash(self):
        """
        Calls all the other methods to process the input. Pads the data, then splits
        into blocks and then does a series of operations for each block (including
        expansion).
        For each block, the variable h that was initialized is copied to a,b,c,d,e
        and these 5 variables a,b,c,d,e undergo several changes. After all the blocks
        are processed, these 5 variables are pairwise added to h ie a to h[0], b to h[1]
        and so on.  This h becomes our final hash which is returned.
        """
        self.padded_data = self.padding()
        self.blocks = self.split_blocks()
        for block in self.blocks:
            expanded_block = self.expand_block(block)
            a, b, c, d, e = self.h
            for i in range(0, 80):
                if 0 <= i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i < 80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                a, b, c, d, e = (
                    self.rotate(a, 5) + f + e + k + expanded_block[i] & 0xFFFFFFFF,
                    a,
                    self.rotate(b, 30),
                    c,
                    d,
                )
            self.h = (
                self.h[0] + a & 0xFFFFFFFF,
                self.h[1] + b & 0xFFFFFFFF,
                self.h[2] + c & 0xFFFFFFFF,
                self.h[3] + d & 0xFFFFFFFF,
                self.h[4] + e & 0xFFFFFFFF,
            )
        return "%08x%08x%08x%08x%08x" % tuple(self.h)




def padding(data):
    """
    Pads the input message with zeros so that padded_data has 64 bytes or 512 bits
    """
    padding = b"\x80" + b"\x00" * (63 - (len(data) + 8) % 64)
    padded_data = data + padding + struct.pack(">Q", 8 * len(data))
    return padded_data


if __name__ == "__main__":
    # digest = b'\x9d\xad\x84y\xdd\x98_W>\x01;\x14.R}T\xe6J\xe3\x9e'

# --------------
# you should n't know the key, just the length, or guess the length...
    key = b"key" * 16
# -------------------



    msg = b"sample message " * 100
    padded_msg = padding(key+msg)
 #   print(padded_msg)

    pad = padded_msg[len(key+msg):]
    print(pad)
    additional_part = b"additional " * 10

    import hashlib

    hg = hashlib.sha1()
    hg.update(key+msg)
    dgst = hg.hexdigest()
    print(dgst)

    for i in range(5):
        print("0x"+dgst[i*8:(i+1)*8])
        i+=1


    # import hashpumpy
    # hashpumpy.hashpump(dgst, msg, additional_part, 16)

