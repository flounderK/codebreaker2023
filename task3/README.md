
# Task 3 - Analyze the Firmware - (Emulation)

```
Leveraging that datasheet enabled you to provide the correct pins and values to properly communicate with the device over UART. Because of this we were able to communicate with the device console and initiate a filesystem dump.

To begin analysis, we loaded the firmware in an analysis tool. The kernel looks to be encrypted, but we found a second-stage bootloader that loads it. The decryption must be happening in this bootloader. There also appears to be a second UART, but we don't see any data coming from it.

Can you find the secret key it uses to decrypt the kernel?

Tips:

You can emulate the loader using the provided QEMU docker container. One download provides the source to build your own. The other is a pre-built docker image. See the README.md from the source download for steps on running it.
Device tree files can be compiled and decompiled with dtc.

Downloads:

U-Boot program loader binary (u-boot.bin)
Recovered Device tree blob file (device_tree.dtb)
Docker source files to build the QEMU/aarch64 image (cbc_qemu_aarch64-source.tar.bz2)
Docker image for QEMU running aarch64 binaries (cbc_qemu_aarch64-image.tar.bz2)
Enter the decryption key u-boot will use.
```

This task was where I started to make a lot of mistakes.

I attempted to import and run the docker image with the following command:
```bash
cat cbc_qemu_aarch64-image.tar | docker import -
docker run -it feba77a54500 bash
```

Which gave me the following error:
```
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: exec: "bash": executable file not found in $PATH: unknown.
```

So I proceeded to completely ignore docker, which was a major mistake. I also failed to ever actually open up the `cbc_qemu_aarch64-source.tar.bz2` file, which would have saved me a significant amount of time, as it contained the specific commands to run `qemu` with.


Instead, I proceeded to put the `u-boot.bin` image into ghidra, where I eventually thought to search for the string `key` and found the string `keyaddr`, which was being passed into a function that I thought might be setting nd environment variable.

```c

  pcVar7 = (char *)env_get(s_keyaddr_4007d494);
  if (pcVar7 == (char *)0x0) {
    pcVar7 = s_467a0000_4007d48b;
    maybe_set_env_str(s_keyaddr_4007d494,s_467a0000_4007d48b);
  }
  lVar8 = env_get(s_ivaddr_4007d49c);

```

I was eventually able to work out this qemu command by looking up which cpu is used in the `BCM2837`:
```bash
qemu-system-aarch64  -cpu cortex-a53 -machine virt -bios u-boot.bin -dtb device_tree.dtb -serial stdio -s -S
```

where I was able to interact with u-boot to print out the environment variable to confirm my suspicion:
```
=> env print keyaddr
keyaddr=467a0000
```

Then I connected to qemu's gdb session with:
```
gdb-multiarch

target remote :1234
```

and checked the address in question:
```
gef➤  x/8ag 0x467a0000
0x467a0000:	0xd2b1fb4e3060a563	0xa16584100a89dc96
0x467a0010:	0x0	0x0
0x467a0020:	0x0	0x0
0x467a0030:	0x0	0x0
gef➤  x/20bx 0x467a0000
0x467a0000:	0x63	0xa5	0x60	0x30	0x4e	0xfb	0xb1	0xd2
0x467a0008:	0x96	0xdc	0x89	0x0a	0x10	0x84	0x65	0xa1
0x467a0010:	0x00	0x00	0x00	0x00
```

Yep that sure does look like bytes. So I submitted
`63a560304efbb1d296dc890a108465a1`

