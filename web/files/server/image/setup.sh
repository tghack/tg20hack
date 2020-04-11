#!/bin/sh

apk upgrade '--no-cache'

echo -e '#!/sbin/openrc-run\ncommand=/hack/challenge.py' > '/etc/init.d/challenge'
echo 'tmpfs /uploads tmpfs rw,size=64K,mode=1777 0 0' >> '/etc/fstab'

chmod -R 755 /etc/init.d
chmod -R 755 /hack

rc-update add devfs boot
rc-update add procfs boot
rc-update add sysfs boot
rc-update add localmount boot
rc-update add challenge default

mkdir -p '/image'
cp -a -r '/bin' '/image/bin'
cp -a -r '/lib' '/image/lib'
cp -a -r '/sbin' '/image/sbin'
cp -a -r '/usr' '/image/usr'
cp -a -r '/etc' '/image/etc'

cp -r '/hack' '/image/hack'
chmod -R 755 '/image/hack'

mkdir '/image/dev'
mkdir '/image/proc'
mkdir '/image/run'
mkdir '/image/sys'
mkdir '/image/var'
mkdir '/image/uploads'

mksquashfs '/image' '/image.squash' '-comp' 'zstd'
rm '-rf' '/image'
