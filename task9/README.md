# Task 9 - Stop the Devices - (Reverse Engineering, Cryptography)
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

```python
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
to fit any command except for the one that starts `diagclient`, the one that
sends a message to navigation, and the one to change collectors, so it should be plenty for now.
Those commands can still be called, I just don't actually have control over the arguments
past argument 2.


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
```c
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
```c
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

After trying to reach this command for a while it appears that ghidra actually just optimized the unreachable case in the switch statement
out.

So I turned to undefined behavior...

Something I noticed while working on task 8 early on was that an hmac key greater than 0x40 bytes will cause a thread to exit early. After looking a little bit more at the main struct that was used everywhere I realized that the hmac buffer in the struct `[1]` is right before the two ints that actually determine whether the the `agent_restart` file is `unlink`ed are actually right past it.


```c
struct main_workstruct {
    char balloon_id0_0x0[4];
    undefined field1_0x4;
    undefined field2_0x5;
    undefined field3_0x6;
    undefined field4_0x7;
    char * * executed_binary_path; /* Created by retype action */
    char * * some_path_0x10; /* Created by retype action */
    struct maybe_linked_list * maybe_linked_list;
    undefined * * pthread_mutex_0x20;
    int * ssh_priv_key_0x28;
    undefined * hmac_key_file_0x30;
    undefined8 collector_0x38;
    undefined8 collector_0x40;
    undefined8 collector_0x48;
    char hmac_key_file_outbuf_0x50[64]; /* Created by retype action */ // [1]
    int is_waiting_for_other_threads_0x90;
    int do_agent_restart_unlink_on_return_to_main_0x94;
    undefined4 collect_enabled_0x98; /* Created by retype action */
    undefined field18_0x9c;
    undefined field19_0x9d;
    undefined field20_0x9e;
    undefined field21_0x9f;
    pointer navigate_ipc_0xa0;
};

struct maybe_linked_list {
    struct allocd_var_struct * field0_0x0;
    struct allocd_var_struct * field1_0x8;
};

struct allocd_var_struct {
    void * field0_0x0;
    void * field1_0x8;
};
```
