insmod hello_driver.ko
mknod /dev/KTMT0 c 250 1
./app_hello_driver /dev/KTMT0
