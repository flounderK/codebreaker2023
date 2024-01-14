
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

No imports from `agent`, libc looks like it is linked in statically.

# Tooling for the VM
Everything in the device firmware is statically linked and `libc` and `ld.so` don't exist on the device, so getting tooling onto the device was a bit of a pain, but also incredibly useful.

## Strace
### Building for aarch64
It turns out that cross compiling strace for aarch64 isn't difficult, but the `strace` project documentation is somewhat lacking.


Install some deps
```bash
sudo apt install gcc-aarch64-linux-gnu
sudo apt install crossbuild-essential-arm64
sudo apt install crossbuild-essential-armel
sudo apt install gcc-arm-linux-gnueabi gcc-arm-none-eabi

# and vsftpd for the file transfer
sudo apt install vsftpd
```

```bash
git clone git@github.com:strace/strace.git
cd strace
./bootstrap
mkdir build
cd build
LDFLAGS='-static -pthread' ARCH='aarch64' CC='aarch64-linux-gnu-gcc' ../configure --enable-mpers=no --host=aarch64-linux
make -j4
cd src
tar -acf strace.tar strace
gzip strace.tar
sudo cp strace.tar.gz ~
```

## gdbserver
If you aren't familliar with `gdbserver`, it is an extremely useful tool for debugging. It lets you debug processes on a remote device and allows you to connect over the network to that device with `gdb` or `gdb-multiarch`. Very convenient if you are creating a `gdbinit` or can't get normal `gdb` to work for the device you are trying to debug things on (like if the device only has statically compiled binaries on it or you want access to `gdb`'s `python` api on a system that you are having trouble building python on).

### Building gdbserver
`gdb` has a few dependencies that I wasn't aware of before, so here are all of the commands that I used to clone and build all of the code I needed to get a statically linked copy of `gdbserver`. Please note that the build process fails sometime after `gdbserver` completes building.
```bash
# clone and build static libraries for gmp

hg clone https://gmplib.org/repo/gmp
cd gmp
./.bootstrap

mkdir build
cd build
ARCH='aarch64' CC='aarch64-linux-gnu-gcc' LD='aarch64-linux-gnu-ld' CXX='aarch64-linux-gnu-g++' LDFLAGS='-static' ../configure --host=aarch64-gnu-linux
make

cd ../..

# clone and build static libraries for mpfr
git clone https://gitlab.inria.fr/mpfr/mpfr.git
cd mpfr
./autogen.sh
mkdir build
cd  build
ARCH='aarch64' CC='aarch64-linux-gnu-gcc' LD='aarch64-linux-gnu-ld' CXX='aarch64-linux-gnu-g++' LDFLAGS='-static' ../configure --host=aarch64-gnu-linux  --with-gmp-build="$HOME/cloned/gmp/build"
make

cd ../..


# clone and build static gdbserver using gmp and mpfr
git clone https://sourceware.org/git/binutils-gdb.git
cd binutils-gdb
mkdir build
cd build
ARCH='aarch64' CC='aarch64-linux-gnu-gcc' LD='aarch64-linux-gnu-ld' CXX='aarch64-linux-gnu-g++' AR='aarch64-linux-gnu-ar' LDFLAGS='-static' ../configure --host=aarch64-gnu-linux --target=aarch64-gnu-linux --with-gmp-lib="$HOME/cloned/gmp/build/.libs/" --with-gmp-include="$HOME/cloned/gmp/build/" --with-mpfr-lib="$HOME/cloned/mpfr/build/src/.libs" --with-mpfr-include="$HOME/cloned/mpfr/src"
make
```

### getting strace onto the target system
I just hosted an `ftp` server on my laptop and ran this command on the vm:
```bash
ftpget -u clif -p '<redacted>' 192.168.1.23 strace.tar.gz
```

# Reversing agent
For any binary that I am reverse engineering, I find that it is extremely useful to identify a few specific functions:
- the `entrypoint`
- logging/debug functions
- functions that interact with the system (syscalls) if they are present
- `memset`/`memcpy`/`memmove`/`str*`
- constructors/destructors if they exist

## entrypoint
Ghidra automatically found the enrypoint, so I just started working from there.

![Unsymbolized entry](../resources/ghidra_agent_unsymbolized_entry.png)

The entrypoint looked a lot like a typical binary linked against libc
![](../resources/ghidra_typical_libc_bin_entry.png)

So I made the assumption that `LAB_00400bf4` was actually `main`.

## logging functions

At least some of the logging functions were immediately apparent just looking at `main`, and with no string obfuscation too.

![](../resources/ghidra_agent_unsymbolized_main.png)

## syscalls
Because `agent` was statically linked, I had to go and find syscalls rather than getting them for free from symbols. So I looked up the syscall calling convention on `aarch64` and found [this stackoverflow question](https://stackoverflow.com/questions/45742869/linux-syscall-conventions-for-armv8).

![](../resources/aarch64_syscall_stackoverflow.png)

So I went and got the bytes for the `svc #0` instruction mentioned in the response.

![](../resources/ipython_aarch64_svc.png)

Then I used ghidra's `Instruction Pattern Search` functionality to search for the bytes:

![](../resources/ghidra_search_for_instruction_pattern.png)

![](../resources/ghidra_instruction_pattern_search_hover_enter_bytes_manually.png)

![](../resources/ghidra_instruction_pattern_search_entered_bytes.png)

Which returned quite a few results:

![](../resources/ghidra_instruction_pattern_search_svc_results.png)

At that point I decided to just start off with the most common syscalls like `read`, `write`, `socket` etc. so I adjusted my search a little bit to show which syscall number was associated with each match.

![](../resources/ghidra_masked_instruction_search.png)

![](../resources/ghidra_masked_search_results.png)

Then I just picked out the syscall numbers that I cared about from [The chromium docs syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm64-64_bit) and manually changed those function names.

## memset/memcpy issues
I was able to identify `memset` and `memcpy` at specific callsites, but after a little while I realized that the arguments for those functions didn't allways match up. It turned out that the thunks for those functions were pointing to unadjusted pointers on the `Global Offset Table (GOT)`, which typically indicates an error processing relocations. Ghidra thought so too:

![](../resources/ghidra_memset_got_plt_bug.png)

I never took the time to resolve this and ended up just working around it instead.

## Dynamic RE
I also had a little bit of success using strace to get an idea of what was happening in `agent`
```bash
/strace -ff -o agent.strace  /agent/agent /agent/config
```

## Agent functionality
### Main
- Reads and parses a config file passed in as an argument to the executable
- allocates a struct (I named it `main_workstruct`) and stores specific vaues from the config file in the struct
- starts three different threads, each of which starts with a log message stating what the name of the thread is
  - `collect_thread`
  - `upload_thread`
  - `cmd_thread`
- also does something related to disabling restart of `agent`


### Upload Thread
- calls `setenv` for `DB_DATABASE`, `DB_COLLECTION`, `DB_URL` to values that I didn't find (it ended up being a bad idea to not try to find the values)
- calls `execve` on a binary that I assumed was `dropper`

### Collect Thread
- Sets up some a device, presumably for data collection

### Cmd Thread
- sets up a `socket`
- waits for new packets on a call to `pselect`
- `read`s in the contents of `/agent/hmac_key` into a buffer embedded in `main_workstruct`
- calls a function that eventually leads to lots of bitshifty math, so I took the liberty of assuming that the function was related to encryption and/or message authentication because it also took the `hmac_key` buffer in as a parameter and compared a value against it. I named this function `do_message_auth_and_decryption` and promptly avoided this function as much as possible
- calls a function associated with the log messages `got command type=%s, nargs=%s` and `command failed`, which I named `handle_commands`
![](../resources/ghidra_command_handler_log_msg.png)


### Reversing Command Handling
If you aren't familiar with ghidra's automatic variable naming convention, it uses something similar to [hungarian notation](https://en.wikipedia.org/wiki/Hungarian_notation) to try to inform you about the types of the variables it has tried to recover. Usually. Sometimes, you end up with variables prefixed with `unaff` or `in_` like `unaff_x19`. These variables indicate uninitialized access to a variable as [this stackexchange question clarifies](https://reverseengineering.stackexchange.com/questions/25372/what-kind-of-function-creates-this-code-pattern). If you see these variables, there is a pretty good chance that a function is missing a parameter in its function signature or something was optimized and you need to enable `In Line` in a function signature. In the case of the `handle_commands` function, there were a few of these variables and it actually looked like they were left over from a `switch` statement where ghidra automatically enabled `In Line` on all of the targets of the jump table related to the `switch`.
![](../resources/ghidra_unaff_registers_handle_commands.png)

It ended up being much easier to just go to the different functions and look at them individually rather than trying to get ghidra to display them correctly, at least for the ones where things didn't look correct.
![](../resources/ghidra_start_diagclient.png)

From there I was able to follow the flow of data pretty well and Identify the structure of the commands

### Agent Commands

- each arg is a char[0x40] buffer,
- max of 10 args

#### 0: stop waiting for other threads and remove restart file
- sets two fields in `main_workstruct`
- on return to `main`, these fields would be checked and would stop all of the other threads and remove the `agent_restart` file

#### 1: Run diagclient
- `fork`s
- runs `setsid`
- runs `setenv` for the following values
  - `SSH_SERVER_ADDRESS` to a value from the command packet
  - `SSH_SERVER_PORT` to a value from the command packet
  - `PRIVATE_KEY_PATH` to `/private/id_ed25519` from the `config` file
  - `SSH_USERNAME` to `nonroot_user` (hardcoded as a string in the binary)
  - `EXPECTED_HOST_KEY` to a value from the command packet
  - `BALLOON_ID` to the contents of `/private/id.txt` from the `config` file
- calls `execve` on `/agent/diagclient` (hardcoded)
- `exit`s in the child process


#### 2: update hmac
- `opens` the file `/agent/hmac_key` from the `config` file
- `write`s a string from teh command packet into the file
- `close`s file

#### 3: set collect enabled
- sets `collect_enabled` to 1 in `main_workstruct`

#### 4: set collect disabled
- sets `collect_enabled` to 0 in `main_workstruct`

#### 5: send message to navigation
- opens a `socket` with `socket(AF_UNIX, SOCK_DGRAM, 0)`
- sets the `dest` addr to `main_workstruct->navigate_ipc` (`/tmp/nav_service.unix` from `config` file)
- sends a 31 byte `buffer`, unsure what the contents mean

#### 6: stop waiting for other threads
- sets a field in `main_workstruct` that will stop the program from waiting for other threads on return to `main`

#### 7: change collectors
- `strndup`s up to 3 string values from command packet and writes them to the 3 `collector` fields in `main_workstruct`


# Reversing dropper
If you haven't had the misfortune to try to reverse-engineer something written in go in ghidra, I can't recommend it. Ghidra is meant to decompile code that was originally written in C or C++, and it does that pretty well overall. Some code can push ghidra to its limits at some points but even then you can usually find a way to make ghidra display the code decently. Go does a lot of things that just **break** ghidra's decompiler. It just violates too many of the assumptions that ghidra relies on about calling convention, stack-depth, stack accesses, etc. for it to actually work correctly. I'm sure that someone has figured out how to make ghidra handle things better, but I haven't found a good way to make it work yet. **Update:** Ghidra 11.0 was released in late December. It helped a tiny bit, but not quite enough to make a difference here.

I found the github repo [https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension](https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension) to be extremely valuable for reverse engineering go. I'm not sure what all the extension does, but it appears to recover some of the type information for go types which can be applied to variables in ghidra.

One of the more useful tricks that I used for go reversing was to middle click on the integer offset from the current stack head to highlight that stack offset across the whole function. While it didn't make things look like ghidra's normal decompiler output for programs written in c/c++, it did help to track variables, which was significantly better from where I was before.
![](../resources/ghidra_go_offset_highlight.png)

Overall I didn't really get a great understanding of what this binary does beyond reading in some sort of config and connecting to a server with `TLS`.


# Answer
I reverse engineered a massive portion of `agent`, partially reverse engineered `dropper`, and found very little pertaining to the task solution after around 8 hours of reversing...

It was a `bz2` compressed blob at the end of `dropper` that was extractable with `binwalk`...

Anyway here is the compressed data:
```
database:
  collection: files
  database: snapshot-f2852ce48e77
  url: mongodb://maintenance:e34adee367a46a@100.107.142.158:27017/?authSource=snapshot-f2852ce48e77
server:
  directory: /tmp/upload
```
