#!/bin/bash

start_build()
{
	make -j$(nproc) vmlinux headers_install modules
	if [[ $? -ne 0 ]]
	then
		return $?
	fi

	KVER=$(sudo make modules_install | rev | cut -d/ -f1 | rev)
	sudo mkinitramfs -o initrd.img $KVER
}

start_kexec()
{
	sudo kexec -l vmlinux --initrd initrd.img --command-line "$(cat /proc/cmdline) nosmap"
	sync
	sudo kexec -e
}

start_build
start_kexec
