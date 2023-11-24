
# Build container

```
sudo docker build -t cbc_qemu_aarch64:latest .
```

# Run container

Put your files in a local directory named `myfiles`, or change the `-v` option to point to another directory in the command below.

```
sudo docker run -it --rm --device=/dev/net/tun:/dev/net/tun --cap-add NET_ADMIN -v $(pwd)/myfiles:/myfiles cbc_qemu_aarch64:latest
```

To get an extra shell in the running container, use `docker exec`:

```
sudo docker ps | grep cbc_qemu_aarch64:latest
sudo docker exec -it <CONTAINER ID> /bin/bash
```

# Run QEMU within the container

## Task 3

To use the virtual serial ports, set up two netcat listeners:

```
# window 1
nc -l 10000

# window 2
nc -l 10001
```

Run QEMU:
```
export UBOOT=/myfiles/u-boot.bin
export DTB=/myfiles/device_tree.dtb

qemu-system-aarch64 -M virt,secure=on -cpu cortex-a53 -bios /myfiles/u-boot.bin -dtb /myfiles/device_tree.dtb -display none -chardev socket,host=localhost,port=10000,id=uart0 -chardev socket,host=localhost,port=10001,id=uart1 -serial chardev:uart0 -serial chardev:uart1
```

## Task 4

```
export KERNEL=/myfiles/kernel8.img
export DTB=/myfiles/bcm2710-rpi-3-b-plus.dtb
export SD_IMG=/myfiles/sd.img
export USB_IMG=/myfiles/usb.img

qemu-system-aarch64 -M raspi3b -m 1G -smp 4 -nographic -append "rw earlyprintk loglevel=8 console=ttyAMA0,115200 dwc_otg.lpm_enable=0 root=/dev/mmcblk0p2 rootdelay=1" -kernel $KERNEL -dtb $DTB -drive if=sd,index=0,format=raw,file=$SD_IMG -drive if=none,id=stick,format=raw,file=$USB_IMG -device usb-storage,drive=stick -netdev type=tap,id=usb0,script=/qemu-ifup,downscript=/qemu-ifdown -device usb-net,netdev=usb0 -netdev type=tap,id=usb1,script=no,downscript=no -device usb-net,netdev=usb1
```

### Enable networking

* The device internal IP is 10.101.255.254.
* The QEMU host (running container) gets the IP 10.101.0.1.

To enable NAT through the QEMU host, run within the running container:

```
iptables -t nat -I POSTROUTING -s 10.101.255.254 -j MASQUERADE
```

And add a default gateway in the QEMU guest:

```
ip route add gw via 10.101.0.1
```
