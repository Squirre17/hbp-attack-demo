#!/bin/bash
gcc exp.c -o fs/exp -Wall -Wextra --static -no-pie
if [ $? -ne 0 ]; then
    exit $?
fi

cd ./fs
find . | cpio -o --format=newc > ../rootfs.cpio
cd ../


    # -kernel ./bzImage \
qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd rootfs.cpio \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr quiet pti=1" \
    -cpu qemu64,+smep,+smap \
    -smp 4 \
    -nographic --no-reboot -monitor /dev/null \
    -snapshot \
    -gdb tcp::1234
