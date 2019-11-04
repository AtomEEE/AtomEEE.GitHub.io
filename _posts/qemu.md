# X86环境下ARM kernel的编译与运行

## QEMU启动Demo

### 开发环境

kali linux

qemu: apt-get install qemu

kernel: curl https://github.com/dhruvvyas90/qemu-rpi-kernel/raw/master/kernel-qemu-4.4.34-jessie

filesystem: 

```bash
1. qemu-img convert -f raw -O qcow2 2017-08-16-raspbian-stretch-lite.img raspbian-stretch-lite.qcow
2. qemu-img resize raspbian-stretch-lite.qcow +6G
```

### 启动命令

```bash
#! /bin/bash
/usr/bin/qemu-system-arm \
           -kernel /root/Documents/LinuxKernel/qemu-rpi-kernel/kernel-qemu-4.4.34-jessie \
           -append "root=/dev/sda2 console=ttyAMA0  panic=1 rootfstype=ext4 rw" \
           -hda /root/Documents/raspbian-stretch-lite.qcow \
           -cpu arm1176 -m 256 \
           -M versatilepb \
           -no-reboot \
           -net nic -net user \
           -net tap,ifname=vnet0,script=no,downscript=no \
           -nographic \
```

## Linux Kernel自编译以及启动

### Linux Kernel编译

1. 下载源码并解压

   源码为Linux kernel 5.3.8

2. 编译设置

   ```bash
   make ARCH=arm versatile_defconfig
   make CROSS_COMPILE=arm-linux-gnueabi- -j 4 all
   ```

   arm-linux-gnueabi- 为交叉编译工具链，需apt下载一下

   ARCH : 选择为arm

   开发板: versatile_defconfig(最开始用的是vexpress，发现无法启动)

   最后生成的img路径：linux/arch/arm/boot/zImange

### Busybox简易文件系统

1. 下载busybox源码并解压

   ```bash
   wget http://www.busybox.net/downloads/busybox-1.21.1.tar.bz2
   tar xjvf busybox-1.21.1.tar.bz2
   ```

2. 交叉编译arm版本的busybox

   ```bash
   make defconfig
   make ARCH=arm
   make menuconfig
   #Busybox Settings ==> Build Options 选择 SELECT Build BusyBox as a static binary(no shared libs)
   make CROSS_COMPILE=arm-linux-gnueabi- -j 4 all
   ```

3. 补充文件系统

   ```bash
   cd _install
   mkdir proc sys dev etc etc/init.d
   touch etc/init.d/rcS
   echo '
   #!/bin/sh
   mount -t proc none /proc
   mount -t sysfs none /sys
   /sbin/mdev -s
   ' > rcs
   chmox +x etc/init.d/rcS
   ```

4. 制作img

   ```bash
   cd busybox-1.21.1
   find . | cpio -o --format=newc > ../rootfs.img
   ```

   

### 启动系统

```bash
qemu-system-arm -M versatilepb -m 256M -kernel linux-5.3.8/arch/arm/boot/zImage -initrd busybox-1.21.1/rootfs.img -append "root=/dev/ram rdinit=/sbin/init" -dtb linux-5.3.8/arch/arm/boot/dts/versatile-pb.dtb  -nographic
```

启动成功，如下图

![success](/img/qemu/success.PNG)

