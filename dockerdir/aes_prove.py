#!/usr/bin/env python3

from Crypto.Cipher import AES


known_ciphertext = bytes.fromhex("27cc abd2 84fa 1394 f529 d7fb a904 736a")
known_ciphertext_2 = bytes.fromhex("258e 3e38 32f7 781e 5a2a a230 5443 933f")
plaintext = bytes.fromhex("ffff ffff ffff ffff ffff ffff ffff ffff")
key = key = bytes.fromhex("d849 2306 0578 8ea4 3794 b1ae c7b8 6032")
iv = bytes.fromhex("79f0 d669 b00a 8db5 0000 0000 0000 0001")
second_iv = bytes.fromhex("79f0 d669 b00a 8db5 0000 0000 0000 0002")
ofb = AES.new(key, AES.MODE_OFB, iv=iv)
ciph_1 = ofb.encrypt(plaintext)
assert ciph_1 == known_ciphertext

ofb = AES.new(key, AES.MODE_OFB, iv=second_iv)
ciph_2 = ofb.encrypt(plaintext)
assert ciph_2 == known_ciphertext_2

print("ofb matched with forced reset")

ctr = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b'')

ctr_ciph_1 = ctr.encrypt(plaintext)
assert ctr_ciph_1 == known_ciphertext

ctr_ciph_2 = ctr.encrypt(plaintext)
assert ctr_ciph_2 == known_ciphertext_2

print("ctr matched")
