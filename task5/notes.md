

Looks like it is going to be go reversing again
```
agent:         ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, BuildID[sha1]=1869a06e4f8a954d335b03f40ae16a9f4b14cf72, for GNU/Linux 3.7.0, stripped
diagclient:    ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=4oj1WczrsazmJatHiYzo/pk0d-pSYXYCrO0k72N5k/Jrw4TwIHYYNgPZ2ku36C/M7MrOXTOwO9s57hyQZRO, with debug_info, not stripped
dropper:       ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, Go BuildID=G1BmcQs3eKWjgqPFtG1u/vjym0bDIzbpAmG4ECqx2/UCIHtpwbefFngLclS-n9/ZJyKNowL1B6arnAtldx0, with debug_info, not stripped
```

No imports from `agent`, libc looks like it is compiled in

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
