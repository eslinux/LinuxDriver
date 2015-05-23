make
gcc app_hello_driver -o app_hello_driver

insmod hello_driver.ko
cat /proc/devices to get major of KTMT­Device
ex: major = 250

mknod /dev/KTMT0 c 250 1
./app_hello_driver /dev/KTMT0
