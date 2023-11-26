# overview

Prompt
```
The security team at Blue Horizon Mobile was able to capture a packet destined to the device under investigation. It looks to be encrypted, and a quick analysis of the firmware show it uses an HMAC scheme for authentication.

Can you decrypt the packet and recover the secret HMAC key the software uses to verify the contents?


Downloads:

Packet capture (capture.pcap)
Enter the HMAC key string used to authenticate the given packet.
```

Provided with a single UDP packet.

Data from the UDP packet:
```
NIST-P256 Elliptic Curve Cryptography data:
    - 0x40 (64) bytes

00000000: 6b17 d1f2 e12c 4247 f8bc e6e5 63a4 40f2  k....,BG....c.@.
00000010: 7703 7d81 2deb 33a0 f4a1 3945 d898 c296  w.}.-.3...9E....
00000020: 4fe3 42e2 fe1a 7f9b 8ee7 eb4a 7c0f 9e16  O.B........J|...
00000030: 2bce 3357 6b31 5ece cbb6 4068 37bf 51f5  +.3Wk1^...@h7.Q.

HMAC hash
    - (sha256sum of a manipulated unknown hmac key and the plaintext for the AES encrypted buffer)
    - 0x20 (32) bytes

00000040: 9aaa 943b 66fa ed7e af57 c1cf 35e3 c88f  ...;f..~.W..5...
00000050: e7ef 2080 0985 0798 ae0c a530 502c f43f  .. ........0P,.?

AES Encrypted buffer
    - (key is determined based on the ECC data in the packet)
    - 0xc0 (192) bytes

00000060: ba46 1296 20f9 1e37 42af e650 cee2 7b8d  .F.. ..7B..P..{.
00000070: 9e81 804f 081e 254d 686e 9577 72d2 3e23  ...O..%Mhn.wr.>#
00000080: 6cb1 00e3 f74e 6cf5 76f0 5d4d 4a58 3e50  l....Nl.v.]MJX>P
00000090: ef6e 8b00 c450 5e93 baaf 92d2 1a00 9b6d  .n...P^........m
000000a0: 711f 70a3 bfb6 18fe 71bc 1729 e04b 318d  q.p.....q..).K1.
000000b0: f7f2 1875 e437 eebe 5b58 5643 88bf 444d  ...u.7..[XVC..DM
000000c0: 2769 3f48 fba7 8e3a 2866 d902 4c83 1203  'i?H...:(f..L...
000000d0: a59c f8b5 db71 7f03 881c 9ea2 22bc e178  .....q......"..x
000000e0: fa5c f9ca 0bbc 1b2a 0caf 67ea ac95 38be  .\.....*..g...8.
000000f0: b233 9658 f86f 6504 a0a5 cd3c 672d 2398  .3.X.oe....<g-#.
00000100: f16f 6e7d f867 51e1 c008 d792 c068 9dae  .on}.gQ......h..
00000110: 7db1 cc16 9179 1a4a a471 c1b6 288a ef09  }....y.J.q..(...
```


ecc_p256_public.bin
```
00000000: 894d 6341 662a 70e3 d4f8 467c 9b25 7bbc  .McAf*p...F|.%{.
00000010: 0ff2 f558 a241 6335 c7d4 8845 532c 8ca6  ...X.Ac5...ES,..
00000020: e172 6175 fb50 ef22 8aa6 55a2 3793 4b8b  .rau.P."..U.7.K.
00000030: 2969 912d 7f29 118d 8b64 bf2d 73f8 d5b8  )i.-.)...d.-s...
```

- ecc_p256_private.bin is 0x60 bytes
- hmac key is 0x40 bytes
    - (can technically be larger or smaller, just so long as it is a string of at least one non-null byte),
    - the update-hmac command is only capable of sending a 0x40 byte hmac

- ecc decrypted data is 0x20 bytes

# TODO
- identify the format of the ecc_p256_public key


# Packet structure
After looking at the command handler functions it is pretty clear that this is the structure of the command payload:
```
// size 0x60
struct CommandHeader {
    byte ecc_encrypted_seed[0x40];
    byte hmac[0x20];
    byte payload[0];
}


// size 0x80+,
struct CommandPayload {
    char command_type_str[0x40];  // this can only actually be the string representation of an integer from 0-7
    char nargs_str[0x40];         // string representing a number of arguments from 0-10
    char args[strtol(nargs_str, 0, 10)][0x40];           // Variable size
}

```


# Decryption Flow
ecc priv key (first 0x20 bytes is used as point coordinates )
|
V
ecc decrypt on 0x20 bytes of the packet at offset 0x20
|
V
sha256 0x20 bytes
|
V
hash is split up and used to seed AES decryption of packet +0x60 bytes
          (only 3/4ths of the hash are actually used, not sure but this might be a weakness)
          (will refer to it as the ECC hash)



AES 128 block-based decryption


ECC HASH (first 16 bytes)
|
|
V
Key Expansion using sbox
            | (expanded key)
            |
            |
            V
/--->-->AES Cipher (unknown mode)  <---- ECC hash bytes[32:48] + round number as IV
|       |
|       |
^       V
|       16 byte Block Key
|       |
|       |
^       V
|       xord with cipher text to decrypt plaintext
|       |
|       |
^       |
|       V
\---<---repeat previous steps after key expansion until all data has been decoded
            |
            |
            V
            AES decrypted command_type_struct (same length as payload bytes)


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



xord_hmac_buf A (0x36)
|
V
sha256  <--- command_type_struct (all of)
|
V
sha256  <--- xord_hmac_buf B (0x5c)
|
V
compared with hmac at 0x40 in packet


This flow means that the hmac key is technically brute force-able without having the ecc p256 private key so long as you know the contents of the aes encrypted buffer ahead of time. Because the serialization of the arguments for each command is a series of char[0x40] buffers and the inputs are strings or have a fairly clear deserialization process, a pretty good guess at the contents of any given payload can be made solely based on the size of the encrypted packet. It is also dependent on the HMAC not being encrypted, which it isn't in this case. (update, this is not feasible because the packet appears to be an hmac-update command, meaning that there is no way to know the contents of the packet ahead of time).

remaining candidates for crypto weaknesses in this:
- points specified for the ecc might not be diverse enough. It looks like the point specified in the private key might be passed in twice, which seems... unwise
- I have not fully reversed the code, but based on the fact that the ecc code is calling a `random` equivalent and nist p256 appears to normally be meant for key exchanges, i think it might be possible that the ecc code is performing a "key exchange" all locally. If this is the case then there is a major weakness in the encryption
- it looks like the aes key that is output from ecc decryption isn't entirely used (as in, some portions of the 32 bytes are zeroed out before being used, which would reduce keyspace somewhat). update, looks like it is just using aes-128 so this is fine

After looking online at a basic aes implementation (https://github.com/kokke/tiny-AES-c/tree/master), it looks like the expanded key size for aes 128 is 176 bytes and the key length is 16 bytes, which matches what I see in `agent`.


# possible AES Modes:
## attributes of the aes impl
- block cipher
    - loops over the function that does decryption and decrypts 0x10 bytes at a time
- 0x10 byte blocks
- is AES 128
- 176 byte expanded key
- 10 rounds per block
- 16 byte key
    - key is the first 16 bytes of the sha256sum of the ecc-encrypted stuff once it is decrypted
- Uses a 16 byte IV
    - first 8 bytes are a portion of the sha256sum of the ecc-encrypted stuff once it is decrypted
    - second 8 bytes can always be known and are just the little-endian index (starting at 1) of the round
- only an SBox was found, not an inverse sbox, which I beleive indicates that the mode uses the same function for encryption as decryption


## valid modes modes
- OFB - matched initially on a live test, current best candidate, but pycryptodome doesn't match after the first run, so a whole new instance needs to be created with the updated IV every time
- CTR - uses outer loop, and increments a value in its IV every time, could very easily be this. Confirmed, This works, it just needs very specific arguments in pycryptodome

**AES is 128 bit in CTR mode**

### Remaining Candidate modes
- CBC - uses outer loop - did not match on initial test
- OCB - does not use IV
- CFB - did not match in a live test

less likely
- OPENPGP
- SIV
- GCM

## incorrect modes
- CCM - no message authentication is done
- ECB - no outer loop
- PCBC - doesn't do the ciphertext ^ plaintext thing for iv generation
- EAX - does not use iv





# commands

- each arg is a char[0x40] buffer,
- max of 10 args

### 0 stop waiting for other threads and remove restart file
- 0 args with arg check

### 1 run diagclient
- 4 args without args check

### 2 update hmac
- 1 arg with arg check

### 3 set collect enabled
- 2 args with arg check

### 4 set collect disabled
- 2 args with arg check

### 5 send message to navigation
- 3 args with arg check
- args are (ip, port, "alt")
- unsure what alt is

### 6 stop waiting for other threads
- no args no arg check

### 7 change collectors
- 3 args with arg check

## Actual Packet
Revisiting the command paylod structre from before:
```
// size 0x80+,
struct CommandPayload {
    char command_type_str[0x40];  // this can only actually be the string
                                  // representation of an integer from 0-7
    char nargs_str[0x40];         // string representing a number of
                                  // arguments from 0-10
    char args[strtol(nargs_str, 0, 10)][0x40];    // Variable size
}
```

Because the packet provided only has `0xc0` bytes for its command payload, the only commands that could be valid would be `2` and `6`.
`2` is the closest match because the number of arguments is necessary for that command is 1, and the size of the command payload header (0x80 bytes) and one argument adds up to 0xc0 bytes. `2` is also the only command that takes 1 argument, making this the only reasonable choice.
`6` would technically be valid because there is no check for the number of arguments for command `6`, however it this was in the packet it would also mean that there is 0x40 bytes of extra useless data, which seems unlikely.

So the actual decrypted contents of the command payload would looks something very similar to this (except with a real new HMAC key)
```
command_bytes = b''.join([b'2'.ljust(0x40, b'\x00'),
                          b'1'.ljust(0x40, b'\x00'),
                          b'NEW-HMAC-KEY'.ljust(0x40, b'\x00')])
```

```
Command Type (UPDATE_HMAC)
00000000: 3200 0000 0000 0000 0000 0000 0000 0000  2...............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................

Number of Arguments
00000040: 3100 0000 0000 0000 0000 0000 0000 0000  1...............
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

New HMAC Key
00000080: 4e45 572d 484d 4143 2d4b 4559 0000 0000  NEW-HMAC-KEY....
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```


and here is the actual packet bytes:
```
7ff6fdb538: 3200 0000 0000 0000 0000 0000 0000 0000  2...............
7ff6fdb548: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb558: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb568: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb578: 3100 0000 0000 0000 0000 0000 0000 0000  1...............
7ff6fdb588: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb598: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb5a8: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb5b8: 7365 6372 6574 5f6b 6579 5f30 3938 3532  secret_key_09852
7ff6fdb5c8: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb5d8: 0000 0000 0000 0000 0000 0000 0000 0000  ................
7ff6fdb5e8: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Using the format from this decrypted packet, I was able to brute force the current hmac key, which was `secret_key_91579`


# Task 9
```
Due to your efforts the security team at Blue Horizon Mobile finally captured packets destined for another Spy Device. You highly suspect in their haste to co-opt and gain access to Blue Horizon Infrastructure, the attackers did not carefully implement their own crypto...

Can you find a way to craft a packet that, if sent to the device, will stop the agent process and prevent it from restarting?


Downloads:

Packet capture (another_device.pcap) [unavailable until prerequisites are completed]

Enter the byte stream in hexidecimal of the packet payload (without the IP or UDP headers).
```

The following 2 packets are found in the provided pcap

packet 2
```
00000000: 6b17 d1f2 e12c 4247 f8bc e6e5 63a4 40f2  k....,BG....c.@.
00000010: 7703 7d81 2deb 33a0 f4a1 3945 d898 c296  w.}.-.3...9E....
00000020: 4fe3 42e2 fe1a 7f9b 8ee7 eb4a 7c0f 9e16  O.B........J|...
00000030: 2bce 3357 6b31 5ece cbb6 4068 37bf 51f5  +.3Wk1^...@h7.Q.

00000040: b654 0b0b 3482 c238 79fc b281 b21e 8f91  .T..4..8y.......
00000050: 2f16 7c18 4ec8 706a 82c8 8ae5 2880 607c  /.|.N.pj....(.`|

00000060: 75d6 5acd cf89 ca68 a28e 4431 4b22 9ed0  u.Z....h..D1K"..
00000070: 36df 20ad 07b1 fc90 9b63 92df e98b 4054  6. ......c....@T
00000080: 3157 4da8 5e0d 98f1 a099 a996 37d4 1911  1WM.^.......7...
00000090: 1b0e 79f8 4621 67ae a2f0 01eb a278 4c1b  ..y.F!g......xL.
000000a0: 144f 95f1 507e d948 68da 697a 6575 6839  .O..P~.Hh.izeuh9
000000b0: 08dd 96a0 64a0 783e 2fe0 65af 18a1 020c  ....d.x>/.e.....
000000c0: e1d8 86d3 1199 2af6 38e0 0945 bcf9 9fe1  ......*.8..E....
000000d0: e800 7d6a b719 e569 6b53 5f85 9326 7a0b  ..}j...ikS_..&z.
000000e0: 3a85 1581 f888 e0e8 9e48 cef1 8fb1 5525  :........H....U%
000000f0: 072c 3c42 e6a4 f4f1 52f6 f7c5 4e68 7f75  .,<B....R...Nh.u
00000100: 7b29 0a29 f0f9 71b1 c501 b97a 169a ee06  {).)..q....z....
00000110: 7a4e 1ff8 5a08 3853 4832 c3a9 5744 2d85  zN..Z.8SH2..WD-.
00000120: a9f4 7022 048f 58d5 306b 9dea c34f 92d8  ..p"..X.0k...O..
00000130: b948 8081 5870 96d5 6084 6caf 2e17 ff43  .H..Xp..`.l....C
00000140: 58ac 91d5 9f75 018d d868 10fa 21c1 940c  X....u...h..!...
00000150: 27cc d781 c4ec 3a93 bf6f c40e 44a0 91f2  '.....:..o..D...
```

```
((0x160 - 0x60) / 0x40)-2 == 2
packet 2 has 2 args
```

packet 3
```
00000000: 6b17 d1f2 e12c 4247 f8bc e6e5 63a4 40f2  k....,BG....c.@.
00000010: 7703 7d81 2deb 33a0 f4a1 3945 d898 c296  w.}.-.3...9E....
00000020: 4fe3 42e2 fe1a 7f9b 8ee7 eb4a 7c0f 9e16  O.B........J|...
00000030: 2bce 3357 6b31 5ece cbb6 4068 37bf 51f5  +.3Wk1^...@h7.Q.

00000040: 3eeb fab7 e31c c805 d4f7 c209 8e19 d0dc  >...............
00000050: 7454 bcd2 18de 1d0d 7722 edfa bc14 df2a  tT......w".....*

00000060: 73d6 5acd cf89 ca68 a28e 4431 4b22 9ed0  s.Z....h..D1K"..
00000070: 36df 20ad 07b1 fc90 9b63 92df e98b 4054  6. ......c....@T
00000080: 3157 4da8 5e0d 98f1 a099 a996 37d4 1911  1WM.^.......7...
00000090: 1b0e 79f8 4621 67ae a2f0 01eb a278 4c1b  ..y.F!g......xL.
000000a0: 154f 95f1 507e d948 68da 697a 6575 6839  .O..P~.Hh.izeuh9
000000b0: 08dd 96a0 64a0 783e 2fe0 65af 18a1 020c  ....d.x>/.e.....
000000c0: e1d8 86d3 1199 2af6 38e0 0945 bcf9 9fe1  ......*.8..E....
000000d0: e800 7d6a b719 e569 6b53 5f85 9326 7a0b  ..}j...ikS_..&z.
000000e0: 20bd 24af c8b9 d3de a671 cef1 8fb1 5525   .$......q....U%
000000f0: 072c 3c42 e6a4 f4f1 52f6 f7c5 4e68 7f75  .,<B....R...Nh.u
00000100: 7b29 0a29 f0f9 71b1 c501 b97a 169a ee06  {).)..q....z....
00000110: 7a4e 1ff8 5a08 3853 4832 c3a9 5744 2d85  zN..Z.8SH2..WD-.
00000120: b5c5 4317 2aba 6ae5 085e aaea c34f 92d8  ..C.*.j..^...O..
00000130: b948 8081 5870 96d5 6084 6caf 2e17 ff43  .H..Xp..`.l....C
00000140: 58ac 91d5 9f75 018d d868 10fa 21c1 940c  X....u...h..!...
00000150: 27cc d781 c4ec 3a93 bf6f c40e 44a0 91f2  '.....:..o..D...
00000160: 2d99 210e 27fd 8397 4bf4 c9b9 3894 9775  -.!.'...K...8..u
00000170: 107f 7a38 8ee5 9eec e2a2 d521 02b5 2ae2  ..z8.......!..*.
00000180: ee93 374e da2d 44d7 9cac 6301 2772 1817  ..7N.-D...c.'r..
00000190: 8658 97f3 9053 2fc1 3726 fdef dcef 2bd9  .X...S/.7&....+.
```

```
((0x1a0 - 0x60) / 0x40)-2 == 3

packet 3 has 3 args
```

## commands
revisiting commands

- each arg is a char[0x40] buffer,
- max of 10 args

### 0 stop waiting for other threads and remove restart file
- 0 args with arg check

### 1 run diagclient
- 4 args without args check

### 2 update hmac
- 1 arg with arg check

### 3 set collect enabled
- 2 args with arg check

### 4 set collect disabled
- 2 args with arg check

### 5 send message to navigation
- 3 args with arg check
- args are (ip, port, "alt")
- unsure what alt is

### 6 stop waiting for other threads
- no args no arg check

### 7 change collectors
- 3 args with arg check

# gathering info on the provided packets
Though I don't have the private or public keys, the way that the AES key is generated is insufficient, as the same key and same IV are generated for each packet (at least for packets going to the same device), so xoring a given encrypted data section with the plaintext that was encrypted for the packet will yield the same encrypted block for each packet. This means that the AES key isn't actually needed to decrypt the packets, the plaintext for one packet just needs to be known to generate the key for each block.

```
p2_cmd_chunk = bytes.fromhex('75d6 5acd cf89 ca68 a28e 4431 4b22 9ed0')
p3_cmd_chunk = bytes.fromhex('73d6 5acd cf89 ca68 a28e 4431 4b22 9ed0')


xor(b'3'.ljust(0x10, b'\x00'), p2_cmd_chunk) == xor(b'5'.ljust(0x10, b'\x00'), p3_cmd_chunk)
```

diffing the packet command data
```
00000000: 0600 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0100 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 1a38 312e 3031 3336 3839 0000 0000 0000  .81.013689......
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 1c31 3335 2e35 3230 3835 3700 0000 0000  .135.520857.....
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```


What the packet 2 plaintext appears to be (from reversing the handler)
```
p2_plaintext = b''.join([b'3'.ljust(0x40, b'\x00'),
                         b'2'.ljust(0x40, b'\x00'),
                         b'1'.ljust(0x40, b'\x00'),
                         b'1'.ljust(0x40, b'\x00')])
00000000: 3300 0000 0000 0000 0000 0000 0000 0000  3...............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 3200 0000 0000 0000 0000 0000 0000 0000  2...............
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 3100 0000 0000 0000 0000 0000 0000 0000  1...............
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 3100 0000 0000 0000 0000 0000 0000 0000  1...............
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

xoring that plaintext with the encrypted packet yields this buffer of encryption key(s?):
```
00000000: 46d6 5acd cf89 ca68 a28e 4431 4b22 9ed0  F.Z....h..D1K"..
00000010: 36df 20ad 07b1 fc90 9b63 92df e98b 4054  6. ......c....@T
00000020: 3157 4da8 5e0d 98f1 a099 a996 37d4 1911  1WM.^.......7...
00000030: 1b0e 79f8 4621 67ae a2f0 01eb a278 4c1b  ..y.F!g......xL.
00000040: 264f 95f1 507e d948 68da 697a 6575 6839  &O..P~.Hh.izeuh9
00000050: 08dd 96a0 64a0 783e 2fe0 65af 18a1 020c  ....d.x>/.e.....
00000060: e1d8 86d3 1199 2af6 38e0 0945 bcf9 9fe1  ......*.8..E....
00000070: e800 7d6a b719 e569 6b53 5f85 9326 7a0b  ..}j...ikS_..&z.
00000080: 0b85 1581 f888 e0e8 9e48 cef1 8fb1 5525  .........H....U%
00000090: 072c 3c42 e6a4 f4f1 52f6 f7c5 4e68 7f75  .,<B....R...Nh.u
000000a0: 7b29 0a29 f0f9 71b1 c501 b97a 169a ee06  {).)..q....z....
000000b0: 7a4e 1ff8 5a08 3853 4832 c3a9 5744 2d85  zN..Z.8SH2..WD-.
000000c0: 98f4 7022 048f 58d5 306b 9dea c34f 92d8  ..p"..X.0k...O..
000000d0: b948 8081 5870 96d5 6084 6caf 2e17 ff43  .H..Xp..`.l....C
000000e0: 58ac 91d5 9f75 018d d868 10fa 21c1 940c  X....u...h..!...
000000f0: 27cc d781 c4ec 3a93 bf6f c40e 44a0 91f2  '.....:..o..D...
```

and when xoring that against the packet 3 data, the packet 3
plaintext is revealed (or atleast most of it, as much of the data as I have of packet 2)

```
00000000: 3500 0000 0000 0000 0000 0000 0000 0000  5...............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 3300 0000 0000 0000 0000 0000 0000 0000  3...............
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 2b38 312e 3031 3336 3839 0000 0000 0000  +81.013689......
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 2d31 3335 2e35 3230 3835 3700 0000 0000  -135.520857.....
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

As a side effect of this property, any arbitrary command packet for this device can be crafted by
xoring the plaintext with the key buffer extracted earlier. There is however a limitation on the
size of packet that can be generated, as only as much key as is available in the second-largest
packet will actually yield anything unless I can determine the plaintext contents of the rest of
packet 3's command. Regardless of this limitation, the buffer extracted so far is enough space
to fit any command except for the one that starts `diagclient`, so it should be plenty for now.


# Finding a command to shut off the device
While reversing for task 8, I noticed that ghidra just won't display one of the command handlers, presumably due to a bug with how it calculated the valid bounds for the switch statement in the command handler function:
```
                             command_switch_vtable                           XREF[2]:     handle_commands:004011f4(*),
                                                                                          _elfSectionHeaders::00000410(*)
        004e3690       addr       command_set_unlink_agent_response_00400d20
                   switchD_00401208::command_switchtable_visible
        004e3698       addr       switchD_00401208::start_diagclient
        004e36a0       addr       switchD_00401208::update_hmac_key
        004e36a8       addr       switchD_00401208::set_collectors_enabled
        004e36b0       addr       switchD_00401208::set_collectors_disabled
        004e36b8       addr       switchD_00401208::send_to_navigation
        004e36c0       addr       switchD_00401208::stop_agent
        004e36c8       addr       switchD_00401208::change_collectors
```

Contents of the command handler that didn't show up
```
bool command_set_unlink_agent_response_00400d20(main_workstruct *param_1,int nargs)

{
  if (nargs == 0) {
    param_1->is_waiting_for_other_threads_0x90 = 0;
    param_1->do_agent_restart_unlink_on_return_to_main_0x94 = 0;
  }
  return nargs == 0;
}
```

Then back in `main`:
```
    *cmd_thread finishes up*
    ...

    if (pvVar7->is_waiting_for_other_threads_0x90 != 1) {
LAB_004008e0:
      log_msg(2,"",0,"waiting for other threads to finish");
      pthread_wait(collect_thread_thread,(undefined8 *)0x0);
      pthread_wait(upload_thread_thread,(undefined8 *)0x0);
      if ((pvVar7->do_agent_restart_unlink_on_return_to_main_0x94 == 0) &&
         (local_1288 != (char *)0x0)) {
        iVar1 = 0;
        log_msg(3,"",0,"removing restart file");
        unlinkat((int)local_1288,__name,iVar1);
      }
```

So this command stops `agent` and `unlink`s the file that would normally allow it to restart.
To be clear, the only reason that I noticed this was because I decided to throw `agent` into `binaryninja` and saw the extra command.

Structure of the command:
```
command STOP_AND_UNLINK_RESTART (0)

00000000: 3000 0000 0000 0000 0000 0000 0000 0000  0...............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................

Number of Arguments (0)

00000040: 3000 0000 0000 0000 0000 0000 0000 0000  0...............
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```
