
# Task 5 - Follow the Data Part 1 - (Reverse Engineering, Forensics)

```
Based on the recovered hardware the device seems to to have an LTE modem and SIM card implying it connects to a GSM telecommunications network. It probably exfiltrates data using this network. Now that you can analyze the entire firmware image, determine where the device is sending data.

Analyze the firmware files and determine the IP address of the system where the device is sending data.

Prompt:

Enter the IP address (don't guess)
```

## Contents of the unencrypted partition
```
╰─$ binwalk sd.img

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1089536       0x10A000        gzip compressed data, has original file name: "Image", from Unix, last modified: 2022-01-17 17:39:46
9007104       0x897000        Flattened device tree, size: 31266 bytes, version: 17
11534336      0xB00000        Linux EXT filesystem, blocks count: 62720, image size: 64225280, rev 1.0, ext3 filesystem data, UUID=8ba104ac-bf4b-46a9-ac0b-d646fd2cfd2c
145751040     0x8AFFC00       Linux EXT filesystem, blocks count: 62720, image size: 64225280, rev 1.0, ext3 filesystem data, UUID=8ba104ac-bf4b-46a9-ac0b-d646fd2cfd2c

...
```

```
sudo -sE
mkdir -p mnt
mount -o loop,offset=0xB00000 ./sd.img ./mnt
cd mnt
```

After poking around for a little bit, I noticed that there weren't very many files, so i did a quick check to see how many were actually present:
```
╰─# find . -type f
./bin/busybox
./bin/dropbearmulti
./bin/openssl
./bin/cryptsetup
./drivers/00_cdc_subset.ko
./drivers/00_dm-mod.ko
./drivers/01_dm-crypt.ko
./etc/resolv.conf
./etc/passwd
./etc/dropbear/dropbear_dss_host_key
./etc/dropbear/dropbear_ecdsa_host_key
./etc/dropbear/dropbear_rsa_host_key
./etc/dropbear/dropbear_ed25519_host_key
./etc/hosts
./etc/udhcpc.script
./etc/fstab
./etc/init.d/rcS
```

Very few files, almost none at all. After looking at most of the non-executable files, the only one with any real contents was `etc/init.d/rcS`, which is a standard path for a startup script.

```
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
/sbin/mdev -s
mount -a

for drv in /drivers/*.ko; do
  insmod $drv
done

[ -s /etc/hostname ] && hostname `cat /etc/hostname`

PRIV_IP=10.101.255.254

ifconfig lo 127.0.0.1 netmask 255.0.0.0
ifconfig lo up
ifconfig usb0 $PRIV_IP netmask 255.255.0.0
ifconfig usb0 up

ifconfig usb1 up
udhcpc -i usb1 -s /etc/udhcpc.script -b &

/sbin/dropbear -p $PRIV_IP:22

/opt/mount_part /dev/sda2 /private /opt/part.enc /agent
(/agent/start >/dev/null 2>&1) &
```

Everything in that file was pretty normal except `/opt/mount_part /dev/sda2 /private /opt/part.enc /agent` and `(/agent/start >/dev/null 2>&1) &`, but since neither of those files were present I assumed that they were just in the encrypted partition.


## Contents of the encrypted partition

```
sudo -sE
echo -n "gabbypray847" | openssl sha1 | awk '{print $NF}' | cryptsetup open part.enc part
mount /dev/mapper/part mnt
╰─# ls -lR mnt
mnt:
total 19936
-rwxr-xr-x 1 root root   891224 May 15  2022 agent
-rw-r--r-- 1 root root        0 May 15  2022 agent_restart
-rw-r----- 1 root root      567 May 15  2022 config
-rwx--x--x 1 root root  7975035 May 15  2022 diagclient
-rwxr-xr-x 1 root root 11483492 May 15  2022 dropper
drwx------ 2 root root    16384 May 15  2022 lost+found
-rwxrwx--- 1 root root      396 May 15  2022 start

mnt/lost+found:
total 0
```

All of the file types:
```
╰─# find mnt | xargs file
mnt:               directory
mnt/lost+found:    directory
mnt/agent_restart: empty
mnt/config:        ASCII text
mnt/dropper:       ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=G1BmcQs3eKWjgqPFtG1u/vjym0bDIzbpAmG4ECqx2/UCIHtpwbefFngLclS-n9/ZJyKNowL1B6arnAtldx0, with debug_info, not stripped
mnt/agent:         ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, BuildID[sha1]=1869a06e4f8a954d335b03f40ae16a9f4b14cf72, for GNU/Linux 3.7.0, stripped
mnt/diagclient:    ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=4oj1WczrsazmJatHiYzo/pk0d-pSYXYCrO0k72N5k/Jrw4TwIHYYNgPZ2ku36C/M7MrOXTOwO9s57hyQZRO, with debug_info, not stripped
mnt/start:         POSIX shell script, ASCII text executable
```

Contents of `start`:
```
╰─# cat mnt/start
#!/bin/sh

DIR=/agent
PROC=agent
RESTART_FILE=agent_restart

# start the navigation service
/bin/nav

mkdir -p /tmp/upload
dmesg > /tmp/upload/boot_log_`date -Iseconds`

# start agent and restart if it exists
while [ 1 ]; do
    if [ ! -e $DIR/$RESTART_FILE ]; then
        break
    fi
    if [ -z "`ps -o comm | egrep ^${PROC}$`" ]; then
        $DIR/$PROC $DIR/config
    fi
    sleep 10
done
```

So `start` appeared to start up a missing binary `/bin/nav`, then start `/agent/agent` in a loop.

Contents of `config`:
```
╰─$ cat config
logfile = "/tmp/log.txt"

# levels 0 (trace) - 5 (fatal)
loglevel = 1

daemonize = true

id_file = "/private/id.txt"
ssh_priv_key = "/private/id_ed25519"
priv_key = "/private/ecc_p256_private.bin"

cmd_host = "0.0.0.0"
cmd_port = 9000

collectors_usb = [ "/dev/ttyUSB0", "/dev/ttyUSB1" ]
collectors_ipc = [ "/tmp/c1.unix", "/tmp/c2.unix" ]
collect_enabled = true
dropper_exe = "/agent/dropper"
dropper_config = "/tmp/dropper.yaml"
dropper_dir = "/tmp/upload"

navigate_ipc = "/tmp/nav_service.unix"

key_file = "/agent/hmac_key"
restart_flag = "/agent/agent_restart"
```

`config` just looks like a config file in a format that I am not familiar with, but overall pretty standard.



Looks like it is going to be go reversing again this year
```
agent:         ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, BuildID[sha1]=1869a06e4f8a954d335b03f40ae16a9f4b14cf72, for GNU/Linux 3.7.0, stripped
diagclient:    ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=4oj1WczrsazmJatHiYzo/pk0d-pSYXYCrO0k72N5k/Jrw4TwIHYYNgPZ2ku36C/M7MrOXTOwO9s57hyQZRO, with debug_info, not stripped
dropper:       ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=G1BmcQs3eKWjgqPFtG1u/vjym0bDIzbpAmG4ECqx2/UCIHtpwbefFngLclS-n9/ZJyKNowL1B6arnAtldx0, with debug_info, not stripped
```

No imports from `agent`, libc looks like it is compiled in

# Reversing agent


# Reversing dropper
If you haven't had the misfortune to try to reverse-engineer something written in go in ghidra, I can't recommend it. Ghidra is meant to decompile code that was originally written in C or C++, and it does that pretty well overall. Some code can push ghidra to its limits at some points but even then you can usually find a way to make ghidra display the code decently. Go does a lot of things that just **break** ghidra's decompiler. It just violates too many of the assumptions that ghidra relies on about calling convention, stack-depth, stack accesses, etc. for it to actually work correctly. I'm sure that someone has figured out
I found the github repo [https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension](https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension) to be extremely valuable for reverse engineering go.


# Answer
I almost entirely reverse engineered `agent` partially reverse engineered `dropper`, and found nothing after around 8 hourse of reversing.

It was a `bz2` compressed blob at the end of `dropper` that was extractable with `binwalk`.

Anyway here is the compressed data:
```
database:
  collection: files
  database: snapshot-f2852ce48e77
  url: mongodb://maintenance:e34adee367a46a@100.107.142.158:27017/?authSource=snapshot-f2852ce48e77
server:
  directory: /tmp/upload
```
