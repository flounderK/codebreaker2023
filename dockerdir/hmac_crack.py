#!/usr/bin/env python3
import hashlib
from hashlib import sha256
from pwn import *
import logging

log = logging.getLogger(__file__)
if not log.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s %(message)s")
    log.addHandler(handler)
log.setLevel(logging.DEBUG)


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

    hex_byte_print_size = bytes_per_line + ((bytes_per_line // bytegroupsize)-1)
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
sha256  <--- decrypted command_type_struct (all of)
| (0x20 bytes of)
V
sha256  <--- xord_hmac_buf B
|
V
compared with hmac at 0x40 in packet
"""

known_command_args_bytes = bytes.fromhex("""
3200 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
3100 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
7365 6372 6574 5f6b 6579 5f30 3938 3532
0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000
""")

# known_command_args_bytes = bytes.fromhex("""
# 3300 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 3200 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 3100 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 3100 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000
# 0000 0000 0000 0000 0000 0000 0000 0000""")


hmac_str_template = b'secret_key_00000'.ljust(0x40, b'\x00')
hmac_str_fmt = hmac_str_template.replace(b'00000', b'%05d')

packet_hmac_hash = bytes.fromhex('''
                                 9aaa 943b 66fa ed7e af57 c1cf 35e3 c88f
                                 e7ef 2080 0985 0798 ae0c a530 502c f43f''')

# packet_hmac_hash = bytes.fromhex('''
# b654 0b0b 3482 c238 79fc b281 b21e 8f91
# 2f16 7c18 4ec8 706a 82c8 8ae5 2880 607c''')
#


for i in range(0, 99999+1):
    hmac_str_padded = hmac_str_fmt % i
    if i % 1000 == 0:
        log.debug("trying %s", str(hmac_str_padded.replace(b'\x00', b'')))

    # hmac_str_padded = hmac_str.ljust(0x40, b'\x00')

    hmac_xord_0x36 = xor(hmac_str_padded, 0x36)
    # print(hexdump_str(hmac_xord_0x36))

    hmac_xord_0x5c = xor(hmac_str_padded, 0x5c)
    # print(hexdump_str(hmac_xord_0x5c))

    s1 = sha256()
    s1.update(hmac_xord_0x36)
    s1.update(known_command_args_bytes)
    # print(s1.hexdigest())

    s2 = sha256()
    s2.update(hmac_xord_0x5c)
    s2.update(s1.digest())
    hash_bytes = s2.digest()
    if hash_bytes == packet_hmac_hash:
        print("found!")
        print(str(hmac_str_padded))
        break
