
extract all of the layers
```
find . -type f -iname 'layer.tar' | xargs -I{} sh -c 'cd $(dirname {}); tar -axf $(basename {}); '
```

Get device tree source
```
dtc  -I dtb -O dts -o device_tree.dts device_tree.dtb
```

## Qemu command
```bash
qemu-system-aarch64  -cpu cortex-a53 -machine virt -bios u-boot.bin -dtb device_tree.dtb -serial stdio -s -S
```


# key:
`63a560304efbb1d296dc890a108465a1`

found with the environment variable `keyaddr`
