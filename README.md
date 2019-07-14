# Extension Framework for FUSE

* LibExtFUSE code Coming soon!

We have modifed the FUSE driver to support ExtFUSE feature. Therefore, you will have to install and run a our modified kernel. To clone the kernel sources do:
```
$ git clone --branch ExtFUSE-1.0 https://github.com/extfuse/linux 
$ cd linux
$ make menuconfig
	Select 'File systems  ---> Extension framework for FUSE' and save/exit.
$ make -j4
$ sudo make install -j4
```

You will also need a modified FUSE library. To clone its source repo:
```
git clone --branch ExtFUSE-1.0 https://github.com/extfuse/libfuse
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
