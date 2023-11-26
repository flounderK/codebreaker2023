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


class PacketGenerator:
    def __init__(self, hmac_key_bytes=b''):
        self.hmac_key_bytes = hmac_key_bytes
        self._aes_cipher = None
        self._command_struct = None

        with open("ecc_p256_public.bin", "rb") as f:
            self.shared_secret = f.read()[:32]

        with open("packet_data.bin", "rb") as f:
            self.ecc_section_bytes = f.read()[:64]


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


    def encrypt_command_struct(self, key, iv):
        log.debug("key=%s iv=%s", str(key), str(iv))
        ctr = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b'')
        encrypted = ctr.encrypt(self._command_struct)
        return encrypted

    def gen_ecc_section(self):
        return self.ecc_section_bytes

    def gen_packet(self, command_type_int, nargs_int, args=None):
        self.gen_command_struct_bytes(command_type_int, nargs_int, args)
        hmac_hash = self.gen_hmac_hash()
        shasum = sha256()
        shasum.update(self.shared_secret)
        shasum_digest_bytes = shasum.digest()
        aes_key = shasum_digest_bytes[:16]
        iv = shasum_digest_bytes[16:24] + b'\x00'*7 + b'\x01'
        encrypted_command_struct = self.encrypt_command_struct(aes_key, iv)

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
    parser.add_argument("command_type", type=functools.partial(int, base=0),
                        help="command type")

    parser.add_argument("nargs", type=functools.partial(int, base=0),
                        help="number of arguments")
    args = parser.parse_args()

    hmac_str = b'secret_key_91579'

    pg = PacketGenerator(hmac_str)
    packet = pg.gen_packet(args.command_type, args.nargs)
    print(hexdump_str(packet))
