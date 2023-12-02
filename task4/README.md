
# Task 4 - Emulate the Firmware - (Dynamic Reverse Engineering, Cryptography)Points: 500

```
We were able to extract the device firmware, however there isn't much visible on it. All the important software might be protected by another method.

There is another disk on a USB device with an interesting file that looks to be an encrypted filesystem. Can you figure out how the system decrypts and mounts it? Recover the password used to decrypt it. You can emulate the device using the QEMU docker container from task 3.


Downloads:

main SD card image (sd.img.bz2)
USB drive image (usb.img.bz2)
Linux kernel (kernel8.img.bz2)
Device tree blob file for emulation (bcm2710-rpi-3-b-plus.dtb.bz2)


Enter the password used to decrypt the filesystem.
```

# Qemu Detour
## Qemu command
qemu-system-aarch64  -cpu cortex-a53 -machine virt -kernel kernel8.img -dtb bcm2710-rpi-3-b-plus.dtb.mod -s -S -serial stdio -device sdhci-pci -device sd-card,drive=sdcarddrive -drive id=sdcarddrive,if=none,format=raw,file=sd.img -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=usbdrive -drive id=usbdrive,if=none,format=raw,file=usb.img


worked once and showed hdmi output, but hasn't since
```
qemu-system-aarch64 -cpu cortex-a53 -smp 4 -machine raspi3ap -kernel kernel8.img -dtb bcm2710-rpi-3-b-plus.dtb -sd sd.img -usb -device usb-storage,drive=myusbdrive -drive id=myusbdrive,if=none,file=usb.img
```

```
qemu-system-aarch64 -cpu cortex-a53 -smp 4 -machine raspi3ap -kernel kernel8.img -dtb bcm2710-rpi-3-b-plus.dtb.mod -usb -device usb-storage,drive=myusbdrive -drive id=myusbdrive,if=none,format=raw,file=usb.img -device sd-card,drive=sdcarddrive -drive id=sdcarddrive,if=none,format=raw,file=sd.img -s
```

It appears that some value might be uninitialized here, as the exact same command line can get to the hdmi or not, and the only different log message is
```
[    5.580281] bcm2708_fb soc:fb: More displays reported from firmware than supported in driver (275435376 vs 3)
[    5.592374] bcm2708_fb soc:fb: FB found 3 display(s)
[    5.671726] Console: switching to colour frame buffer device 100x30
[    5.700244] bcm2708_fb soc:fb: Registered framebuffer for display 0, size 800x480
[    5.742166] bcm2708_fb soc:fb: Registered framebuffer for display 1, size 800x480
[    5.790930] bcm2708_fb soc:fb: Registered framebuffer for display 2, size 800x480
```
where `275435376` happens to be the second half of a pointer to `bcm2708_fb_probe`
```
qemu-system-aarch64 -cpu cortex-a53 -machine raspi3ap -kernel kernel8.img -dtb bcm2710-rpi-3-b-plus.dtb.mod -usb -device usb-storage,drive=myusbdrive -drive id=myusbdrive,if=none,format=raw,file=usb.img -device sd-card,drive=sdcarddrive -drive id=sdcarddrive,if=none,format=raw,file=sd.img -s -S
```

This seems to get a bit further:
```
qemu-system-aarch64 -cpu cortex-a53 -machine raspi3b -kernel kernel8.img -dtb bcm2710-rpi-3-b-plus.dtb.mod -usb -device usb-storage,drive=myusbdrive -drive id=myusbdrive,if=none,format=raw,file=usb.img -device sd-card,drive=sdcarddrive -drive id=sdcarddrive,if=none,format=raw,file=sd.img -s -S
```


## using the virt machine type
```
qemu-system-aarch64 -cpu cortex-a53 -machine virt -kernel kernel8.img -dtb bcm2710-rpi-3-b-plus.dtb.mod -usb -device usb-ehci,id=ehci -device usb-storage,drive=myusbdrive,id=ehci.0 -drive id=myusbdrive,if=none,format=raw,file=usb.img -device sdhci-pci -device sd-card,drive=sdcarddrive -drive id=sdcarddrive,if=none,format=raw,file=sd.img
```


# Actual solution
Looks like qemu was completely unnecessary, the encrypted drive actually only has 3 bytes of entropy at most, it just requires time to brute force the password because validation uses `cryptsetup`.

Get the partition offset for `usb.img`
```
╰─$ binwalk usb.img

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1048576       0x100000        Linux EXT filesystem, blocks count: 15360, image size: 15728640, rev 1.0, ext3 filesystem data, UUID=ff61e7cd-4b5b-490d-8776-ad31f891f891
```


mount it
```
mkdir mnt
sudo mount -o loop,offset=0x100000 ./usb.img ./mnt

╰─# ls -lR mnt
mnt:
total 28728
-rw-r--r-- 1 root root       10 May 15  2022 hostname
drwx------ 2 root root    16384 May 15  2022 lost+found
-rwxrwx--- 1 root root      443 May 15  2022 mount_part
-rw-r--r-- 1 root root 29360128 May 15  2022 part.enc

mnt/lost+found:
total 0

```


Looks like decryption is only a matter of getting the value of `$DATA`:
```bash
╰─# cat mnt/mount_part
#!/bin/sh

SEC_DRIVE=$1
SEC_MOUNT=$2
ENC_PARTITION=$3
ENC_MOUNT=$4

[ ! -e $ENC_PARTITION ] && { echo "encrypted partition not found"; exit 1; }

mkdir -p $SEC_MOUNT
mount $SEC_DRIVE $SEC_MOUNT
NAME=`hostname`
ID=`cat /private/id.txt`

DATA="${NAME}${ID:0:3}"
echo "cryptsetup: opening $ENC_PARTITION"
echo -n $DATA | openssl sha1 | awk '{print $NF}' | cryptsetup open $ENC_PARTITION part
mkdir -p $ENC_MOUNT
mount /dev/mapper/part $ENC_MOUNT
```

`${ID:0:3}` gets bytes 0-3 of the string in `$ID`, and `hostname` is already present, meaning that there are only 3 bytes of the key that aren't known.
```
╰─# cat mnt/hostname
gabbypray
```

Unfortunately `id.txt` wasn't present anywhere, but 3 bytes is easy enough to brute force.

At first I just tried to write a python script to brute force the password by running the command  `echo -n $DATA | openssl sha1 | awk '{print $NF}' | cryptsetup open $ENC_PARTITION part` and changing the value of `$DATA` every time, but it turns out that running a few bash command on a single thread is really slow.

here is roughly the command I needed to run to brute force it:
```
bruteforce-luks -f only_hashes -t 6 -v 30 part.enc -w bruteforce_state
```

But at my best estimate at 0.6 passwords per second that would take...
```
In [4]: ((int(238329.0 / 0.6) / 60) / 60 ) / 24
Out[4]: 4.597395833333334
```
Around `4.6` days in which I wouldn't be able to use my laptop at all.
Instead, I opted to use a cloud compute provider and just rent a few virtual machines.

```
# generate a list of unique hashes to use as passwords
python3 gethashes.py
# whoops, duplicated some
cat hashes| sort | uniq > ../unique_hashes
cat unique_hashes| cut -d ' ' -f3 > only_hashes

╰─$ wc only_hashes
 238329  238328 9771449 only_hashes

# split up the text into a few different files
split --lines=$(python3 -c 'print(int(int(238329 + 8 - 1) / 8))') only_hashes

# then start up 8 different brute forcers to make things go quicker
./send_to_ubuntu.sh <ip> <subset of hashes>
ssh ubuntu@<ip-address>
$ tmux
$ ./start_cmd.sh
```

At roughly 1.6 passwords per second, I expected it to take a little over 5 hours to complete, much better than old estimate of `4.6` days
```
In [2]: ((int(238329.0 / 1.6) / 60) / 60 ) / 8
Out[2]: 5.172048611111111
```

Aaaand one of them found the password in under an hour, way faster than expected:
```
Password found: e49d636fe52fef19144b14af707ec89424d24130
```

```
grep 'e49d636fe52fef19144b14af707ec89424d24130' unique_hashes
 gabbypray847 SHA1(stdin)= e49d636fe52fef19144b14af707ec89424d24130
```


At $0.24/hr, with 8 compute resources each with 8 vCPUs running under an hour, not a bad use of $1.92


# actually mount the drive
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

Then to close:
```
cryptsetup close part
```

