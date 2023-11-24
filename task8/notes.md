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



- ecc_p256_private.bin is 0x60 bytes
- hmac key is 0x40 bytes
    - (can technically be larger or smaller, just so long as it is a string of at least one non-null byte),
    - the update-hmac command is only capable of sending a 0x40 byte hmac

- ecc decrypted data is 0x20 bytes

# TODO
- identify the format of the ecc_p256_public key


# Packet structure
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
- it looks like the aes key that is output from ecc decryption isn't entirely used (as in, some portions of the 32 bytes are zeroed out before being used, which would reduce keyspace somewhat).

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

**CTR**

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

# Task 9
```
Due to your efforts the security team at Blue Horizon Mobile finally captured packets destined for another Spy Device. You highly suspect in their haste to co-opt and gain access to Blue Horizon Infrastructure, the attackers did not carefully implement their own crypto...

Can you find a way to craft a packet that, if sent to the device, will stop the agent process and prevent it from restarting?


Downloads:

Packet capture (another_device.pcap) [unavailable until prerequisites are completed]

Enter the byte stream in hexidecimal of the packet payload (without the IP or UDP headers).
```

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
