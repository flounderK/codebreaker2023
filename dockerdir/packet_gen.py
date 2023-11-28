#!/usr/bin/env python3
import hashlib
from hashlib import sha256
from Crypto.Cipher import AES
from pwn import *
import argparse
import functools

log = logging.getLogger(__file__)
if not log.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s %(message)s")
    log.addHandler(handler)
log.setLevel(logging.WARNING)



def batch(it, sz):
    for i in range(0, len(it), sz):
        yield it[i:i+sz]

def hexdump_str(bytevals, offset=0, bytes_per_line=16, bytegroupsize=2):
    # get max address size
    max_address = len(bytevals) + offset
    curr_addr = max_address
    address_chr_count = 0
    while curr_addr > 0:
        curr_addr = curr_addr >> 4
        address_chr_count += 1

    if address_chr_count < 8:
        address_chr_count = 8

    hex_byte_print_size = (bytes_per_line*2) + ((bytes_per_line // bytegroupsize)-1)
    # generate a line formatstring specifying max widths
    line_fmtstr = '%%0%dx: %%-%ds  %%s' % (address_chr_count,
                                           hex_byte_print_size)
    printable_char_ints = set(string.printable[:-5].encode())

    outlines = []
    for line_num, byteline in enumerate(batch(bytevals, bytes_per_line)):
        line_bytegroups = []
        line_strchrs = ""
        addr = (line_num*bytes_per_line) + offset
        for bytegroup in batch(byteline, bytegroupsize):
            bytegroup_str = ''.join(['%02x' % i for i in bytegroup])
            line_bytegroups.append(bytegroup.hex())
            for b in bytegroup:
                # force the value to stay as a byte instead of converting
                # to an integer
                if b in printable_char_ints:
                    line_strchrs += chr(b)
                else:
                    line_strchrs += '.'
        hex_bytes = ' '.join(line_bytegroups)
        out_line = line_fmtstr % (addr, hex_bytes, line_strchrs)
        outlines.append(out_line)

    return '\n'.join(outlines)


"""
ecc priv key
|
V
ecc decrypt on the first ~32-64 bytes of the packet
|
V
sha256 0x20 bytes
|
V
hash is split up and used to seed AES decryption of packet +0x60 bytes
|
V
AES decrypted command_type_struct (SAME LENGTH AS payload bytes)


HMAC key
|
V
SHA256 (if hmac strlen > 0x40)
|
V
xor with b'\\' or b'6'
|
V
xord_hmac_buf A and B

xord_hmac_buf A
|
V
sha256  <--- command_type_struct (all of)
| (0x20 bytes of)
V
sha256  <--- xord_hmac_buf B
|
V
compared with hmac at 0x40 in packet
"""


T9_ENCRYPTION_KEY = bytes.fromhex("""
46d6 5acd cf89 ca68 a28e 4431 4b22 9ed0
36df 20ad 07b1 fc90 9b63 92df e98b 4054
3157 4da8 5e0d 98f1 a099 a996 37d4 1911
1b0e 79f8 4621 67ae a2f0 01eb a278 4c1b
264f 95f1 507e d948 68da 697a 6575 6839
08dd 96a0 64a0 783e 2fe0 65af 18a1 020c
e1d8 86d3 1199 2af6 38e0 0945 bcf9 9fe1
e800 7d6a b719 e569 6b53 5f85 9326 7a0b
0b85 1581 f888 e0e8 9e48 cef1 8fb1 5525
072c 3c42 e6a4 f4f1 52f6 f7c5 4e68 7f75
7b29 0a29 f0f9 71b1 c501 b97a 169a ee06
7a4e 1ff8 5a08 3853 4832 c3a9 5744 2d85
98f4 7022 048f 58d5 306b 9dea c34f 92d8
b948 8081 5870 96d5 6084 6caf 2e17 ff43
58ac 91d5 9f75 018d d868 10fa 21c1 940c
27cc d781 c4ec 3a93 bf6f c40e 44a0 91f2
""")


class PacketGenerator:
    def __init__(self, hmac_key_bytes, ecc_section_bytes, shared_secret=None, aes_key_buffer=None):
        self.hmac_key_bytes = hmac_key_bytes
        self._aes_cipher = None
        self._command_struct = None

        self.shared_secret = shared_secret
        self.ecc_section_bytes = ecc_section_bytes
        self.aes_key_buffer = aes_key_buffer


    def gen_command_struct_bytes(self, command_type_int, nargs_int, args=None):
        if args is None:
            args = []

        command_type_bytes = str(command_type_int).encode().ljust(0x40, b'\x00')
        nargs_bytes = str(nargs_int).encode().ljust(0x40, b'\x00')
        args_bytes = b''.join([i.ljust(0x40, b'\x00') for i in args])
        command_struct_bytes = b''.join([command_type_bytes, nargs_bytes, args_bytes])
        self._command_struct = command_struct_bytes
        log.debug("command struct")
        log.debug("%s", hexdump_str(command_struct_bytes))
        log.debug("")
        return command_struct_bytes

    def encrypt_command_struct(self, key=None, iv=None):
        # TODO: this is horrible
        if (key is None or (iv is None)) and self.shared_secret is not None:
            key, iv = self.gen_aes_key_and_iv()
        elif self.aes_key_buffer is not None:
            return xor(self._command_struct, self.aes_key_buffer)
        log.debug("key=%s iv=%s", str(key), str(iv))
        ctr = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b'')
        encrypted = ctr.encrypt(self._command_struct)
        return encrypted

    def gen_ecc_section(self):
        return self.ecc_section_bytes

    def gen_aes_key_and_iv(self):
        shasum = sha256()
        shasum.update(self.shared_secret)
        shasum_digest_bytes = shasum.digest()
        aes_key = shasum_digest_bytes[:16]
        iv = shasum_digest_bytes[16:24] + b'\x00'*7 + b'\x01'
        return aes_key, iv

    def gen_packet(self, command_type_int, nargs_int, args=None):
        self.gen_command_struct_bytes(command_type_int, nargs_int, args)
        hmac_hash = self.gen_hmac_hash()
        encrypted_command_struct = self.encrypt_command_struct()

        ecc_section_bytes = self.gen_ecc_section()
        packet = b''.join([ecc_section_bytes, hmac_hash,
                           encrypted_command_struct])
        return packet

    def gen_hmac_hash(self):
        if isinstance(self.hmac_key_bytes, str):
            self.hmac_key_bytes = self.hmac_key_bytes.encode()

        log.debug("generating hmac, key=%s", str(self.hmac_key_bytes))

        hmac_key_bytes_padded = self.hmac_key_bytes.ljust(0x40, b'\x00')
        log.debug("padded")
        log.debug("%s", hexdump_str(hmac_key_bytes_padded))
        log.debug("")

        hmac_xord_0x36 = xor(hmac_key_bytes_padded, 0x36)
        log.debug("xor 0x36 (6)")
        log.debug("%s", hexdump_str(hmac_xord_0x36))
        log.debug("")
        # print(hexdump_str(hmac_xord_0x36))

        hmac_xord_0x5c = xor(hmac_key_bytes_padded, 0x5c)
        log.debug("xor 0x5c (\)")
        log.debug("%s", hexdump_str(hmac_xord_0x5c))
        log.debug("")
        # print(hexdump_str(hmac_xord_0x5c))

        s1 = sha256()
        log.debug("update sha256 A with hmac key xord 0x36")
        s1.update(hmac_xord_0x36)
        log.debug("update sha256 A with command_struct")
        s1.update(bytes(self._command_struct))
        log.debug("sha256 A %s", s1.hexdigest())
        # print(s1.hexdigest())

        s2 = sha256()
        log.debug("update sha256 B with hmac key xord 0x5c")
        s2.update(hmac_xord_0x5c)
        s2.update(s1.digest())
        log.debug("sha256 B %s",s2.hexdigest())
        return s2.digest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", default=False)
    parser.add_argument("command_type", type=functools.partial(int, base=0),
                        help="command type")

    parser.add_argument("nargs", type=functools.partial(int, base=0),
                        help="number of arguments")
    parser.add_argument("args", type=str, nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.debug is True:
        log.setLevel(logging.DEBUG)
        log.debug("args %s", str(args))

    args.args = [i.encode() for i in args.args]

    hmac_str = b'secret_key_91579'

    with open("ecc_p256_public.bin", "rb") as f:
        shared_secret = f.read()[:32]

    with open("packet_data.bin", "rb") as f:
        ecc_section_bytes = f.read()[:64]

    pg = PacketGenerator(hmac_str, ecc_section_bytes, shared_secret=shared_secret)
    packet = pg.gen_packet(args.command_type, args.nargs, args.args)
    print(hexdump_str(packet))
