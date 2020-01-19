# Extension Framework for FUSE

We have modifed the FUSE driver to support ExtFUSE feature. Therefore, you will have to install and run a our modified kernel. To clone the kernel sources do:
```
$ git clone --branch ExtFUSE-1.0 https://github.com/extfuse/linux 
$ cd linux
$ make menuconfig
	Select 'File systems  ---> Extension framework for FUSE' and save/exit.
$ make -j4
$ sudo make install -j4
```

Boot into the new kernel. Clone ExtFUSE library sources and build. You will need LLVM/Clang toolchain.
```
$ git clone https://github.com/extfuse/extfuse
$ cd extfuse
$ LLC=llc-3.8 CLANG=clang-3.8 make
```

The eBPF code for handling FUSE requests in the kernel can be found in ```bpf/extfuse.c```.
Once you build the library, compiled eBPF bytecode can be found in ```src/extfuse.o```.

Finally, you will also need a modified FUSE library. To clone its source repo:
```
$ git clone --branch ExtFUSE-1.0 https://github.com/extfuse/libfuse
```
Follow instructions [here](https://github.com/libfuse/libfuse/blob/master/README.md) to build libfuse.

You can test ExtFUSE functionality with a simple stackable FUSE file system [here](https://github.com/ashishbijlani/StackFS).
```
$ git clone https://github.com/ashishbijlani/StackFS
$ cd StackFS
$ make
$ export LIB_PATH=$HOME/libfuse/lib/.libs:$HOME/extfuse
$ sudo sh -c "LD_LIBRARY_PATH=$LIB_PATH ./StackFS_ll -o max_write=131072 -o writeback_cache -o splice_read -o splice_write -o splice_move -r $ROOT_DIR $MNT_DIR -o allow_other"
```

* [Open Source Summit, 2018 Presentation](https://events.linuxfoundation.org/wp-content/uploads/2017/11/When-eBPF-Meets-FUSE-Improving-Performance-of-User-File-Systems-Ashish-Bijlani-Georgia-Tech.pdf)

* [LPC'18 Video](https://www.youtube.com/watch?v=XmoJCHNEp2w)

* If you use this work for your research, we would deep appreciate a citation to our USENIX ATC '19 [Paper](https://www.usenix.org/system/files/atc19-bijlani.pdf)

```
@inproceedings {234870,
author = {Ashish Bijlani and Umakishore Ramachandran},
title = {Extension Framework for File Systems in User space},
booktitle = {2019 {USENIX} Annual Technical Conference ({USENIX} {ATC} 19)},
year = {2019},
isbn = {978-1-939133-03-8},
address = {Renton, WA},
pages = {121--134},
url = {https://www.usenix.org/conference/atc19/presentation/bijlani},
publisher = {{USENIX} Association},
}
```
