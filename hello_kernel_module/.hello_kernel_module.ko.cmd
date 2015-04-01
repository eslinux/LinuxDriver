<<<<<<< HEAD
cmd_/home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.ko := /home/ninhld/freescale/SDK/7420LBV1170/cross_compiler/fsl-linaro-toolchain/bin/arm-none-linux-gnueabi-ld -EL -r  -T /home/ninhld/freescale/SDK/7420LBV1170/source/linux-3.0.35/scripts/module-common.lds --build-id  -o /home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.ko /home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.o /home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.mod.o
=======
cmd_/home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.ko := ld -r -m elf_x86_64 -T ./scripts/module-common.lds --build-id  -o /home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.ko /home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.o /home/ninhld/Github/LinuxDriver/hello_kernel_module/hello_kernel_module.mod.o
>>>>>>> 2d441b1d4aab0b1291371a4f5dce607f793bd8ac
