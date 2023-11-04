#!/bin/sh

export KERNEL=kernel8.img
export DTB=bcm2710-rpi-3-b-plus.dtb
export SD_IMG=sd.img
export USB_IMG=usb.img

qemu-system-aarch64 -M raspi3b -m 1G -smp 4 -nographic -append "rw earlyprintk loglevel=8 console=ttyAMA0,115200 dwc_otg.lpm_enable=0 root=/dev/mmcblk0p2 rootdelay=1" -kernel $KERNEL -dtb $DTB -drive if=sd,index=0,format=raw,file=$SD_IMG -drive if=none,id=stick,format=raw,file=$USB_IMG -device usb-storage,drive=stick -netdev type=tap,id=usb0,script=/qemu-ifup,downscript=/qemu-ifdown -device usb-net,netdev=usb0 -netdev type=tap,id=usb1,script=no,downscript=no -device usb-net,netdev=usb1

