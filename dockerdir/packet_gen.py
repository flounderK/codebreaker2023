#!/usr/bin/env python3
import hashlib
from hashlib import sha256
from Crypto.Cipher import AES
from pwn import *

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

known_command_args_bytes = bytes.fromhex("""
13e3 e16c ba4a 9fae 2fed 2ec1 f21a c43e
287f 074c 3ae8 21df f265 78ad 06ff 735e
a849 5aad b061 dfed dd0b 5fe9 a0d3 82f7
c03b 0257 93d6 85c8 e4f6 8c2f e394 8fa1
e750 f122 4bc9 ba70 c465 3685 de30 a980
747f 53e8 8c8c 7c9c eefc ea48 5c34 83cc
8b6a 65fc 074b 2240 c141 fdf3 d210 5d4c
a52d a6c9 aa37 7f91 72ce d1ef 291a 8772
b842 8256 5e68 4917 47c8 1538 7082 4746
5143 92f0 52d1 df61 e445 22b3 9b3a bf5a
e247 8a30 1e9d 2a5c f2f5 58a5 94fc 8ac5
32b0 76ea 4ba6 99ac d229 7df1 ad8c 07d7
""")

cleartext_data = bytes.fromhex('''ba46 1296 20f9 1e37 42af e650 cee2 7b8d
9e81 804f 081e 254d 686e 9577 72d2 3e23
6cb1 00e3 f74e 6cf5 76f0 5d4d 4a58 3e50
ef6e 8b00 c450 5e93 baaf 92d2 1a00 9b6d
711f 70a3 bfb6 18fe 71bc 1729 e04b 318d
f7f2 1875 e437 eebe 5b58 5643 88bf 444d
2769 3f48 fba7 8e3a 2866 d902 4c83 1203
a59c f8b5 db71 7f03 881c 9ea2 22bc e178
fa5c f9ca 0bbc 1b2a 0caf 67ea ac95 38be
b233 9658 f86f 6504 a0a5 cd3c 672d 2398
f16f 6e7d f867 51e1 c008 d792 c068 9dae
7db1 cc16 9179 1a4a a471 c1b6 288a ef09
''')


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



hmac_str = b'secret_key_91579'

pg = PacketGenerator(hmac_str)
packet = pg.gen_packet(-1, 0)
print(hexdump_str(packet))
