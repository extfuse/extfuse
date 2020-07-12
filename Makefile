#
# Based on linux/samples/bpf/Makefile
#

# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# List of programs to build
hostprogs-y := libextfuse.so

libextfuse.so-objs := \
	src/ebpf.o src/libbpf.o src/bpf_load.o

# Generate .c files based on kernel source
%.c:
	cp $(objtree)/samples/bpf/bpf_load.c $(PWD)/src/.
	if [ -f $(objtree)/samples/bpf/libbpf.c ]; then \
		cp $(objtree)/samples/bpf/libbpf.c $(PWD)/src/.; \
	else \
		cp $(objtree)/tools/lib/bpf/bpf.c $(PWD)/src/libbpf.c; \
	fi;

# Tell kbuild to always build the programs
always := $(hostprogs-y)
always += bpf/extfuse.o

EXTRA_CFLAGS += -I$(PWD)/include -I$(objtree)/samples/bpf
ifneq ("$(wildcard $(srctree)/samples/bpf/asm_goto_workaround.h)","")
	EXTRA_CFLAGS += -I$(srctree)/samples/bpf/ -include asm_goto_workaround.h
endif

ifdef HOSTCFLAGS
HOSTCFLAGS += -fPIC -I$(PWD)/include
HOSTCFLAGS += -I$(objtree)/usr/include
HOSTCFLAGS += -I$(objtree)/samples/bpf
HOSTCFLAGS += -I$(objtree)/tools/lib/bpf
HOSTCFLAGS += -I$(objtree)/tools/lib -I$(srctree)/tools/include
HOSTCFLAGS += -I$(srctree)/tools/perf
HOSTLOADLIBES_libextfuse.so += -shared -lelf -lpthread
else
KBUILD_HOSTCFLAGS += -fPIC -I$(PWD)/include
KBUILD_HOSTCFLAGS += -I$(objtree)/usr/include
KBUILD_HOSTCFLAGS += -I$(srctree)/samples/bpf
KBUILD_HOSTCFLAGS += -I$(srctree)/tools/lib/bpf
KBUILD_HOSTCFLAGS += -I$(srctree)/tools/testing/selftests/bpf/
KBUILD_HOSTCFLAGS += -I$(srctree)/tools/lib -I$(srctree)/tools/include
KBUILD_HOSTCFLAGS += -I$(srctree)/tools/perf
HOSTLDLIBS_libextfuse.so += -shared -lelf -lpthread
endif

HOSTCFLAGS_bpf_load.o += -I$(objtree)/usr/include -Wno-unused-variable
HOSTCFLAGS_libbpf.o += -I$(objtree)/usr/include -Wno-unused-variable

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C /lib/modules/`uname -r`/build M=${PWD}

clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=${PWD} clean
	rm -f src/*.o bpf/*.o *.so
	rm -f src/libbpf.c src/bpf_load.c

# Verify LLVM compiler tools are available and bpf target is supported by llc
.PHONY: verify_cmds verify_target_bpf $(CLANG) $(LLC)

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

$(src)/*.c: verify_target_bpf

# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
$(obj)/%.o: $(src)/%.c
	$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-I$(srctree)/tools/testing/selftests/bpf/ -I$(srctree)/fs/fuse/ \
		-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@
