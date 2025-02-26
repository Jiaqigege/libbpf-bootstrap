# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../libbpf/src)
BPFTOOL_SRC := $(abspath ../../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../../blazesym/)
LIBBLAZESYM_CARGO_TARGET := $(LIBBLAZESYM_SRC)/target/release/libblazesym_c.a
LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/capi/include)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym_c.a)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../../vmlinux.h/include/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC)
CFLAGS := -g -Wall
CXXFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = minimal minimal_legacy minimal_ns bootstrap uprobe kprobe fentry \
       usdt sockfilter tc ksyscall task_iter lsm openat bootstrap_igsys uprobe_userapi
USER_APP = uprobe_userapi_app
CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := profile
APPS += $(BZS_APPS) 
# Required by libblazesym
ALL_LDFLAGS += -lrt -ldl -lpthread -lm
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg = @printf ' \033[33;44m%-8s %s%s\033[0m\n' \
			"$(1)"						\
			"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
			"$(if $(3), $(3))";
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,CXX,$(CROSS_COMPILE)c++)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS) $(USER_APP)

.PHONY: env
env: $(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(LIBBPF_OBJ) $(BPFTOOL) $(LIBBLAZESYM_OBJ)

.PHONY: bpftool
bpftool: $(BPFTOOL_OUTPUT) $(BPFTOOL) $(LIBBLAZESYM_OBJ)

BPF_SRC   := $(wildcard *.bpf.c)
BPF_SKELS := $(patsubst %.bpf.c,$(OUTPUT)/%.skel.h,$(BPF_SRC))
.PHONY: bpf
bpf: $(BPF_SKELS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -f $(OUTPUT)/*.o $(OUTPUT)/*.h $(APPS)

.PHONY: distclean
distclean:
	$(call msg,DISTCLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

.PHONY: mrproper
mrproper:
	$(call msg,MRPROPER)
	$(Q)rm -rf $(OUTPUT) $(APPS)
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) clean

# environment
## create directory
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

## Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

## Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

## Build Rust lib blazesym_c
${LIBBLAZESYM_CARGO_TARGET}::
	$(call msg,LIB, $@)
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --package=blazesym-c --release

## Copy Rust lib blazesym_c
$(LIBBLAZESYM_OBJ): ${LIBBLAZESYM_CARGO_TARGET} | $(OUTPUT)
	$(call msg,COPY_LIB, $@)
	$(Q)cp ${LIBBLAZESYM_CARGO_TARGET} $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h


$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.o: %.cpp $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CXX) $(CXXFLAGS) $(INCLUDES) -c $(filter %.cpp,$^) -o $@


# profile specify blazesym_c
$(patsubst %,$(OUTPUT)/%.o,$(BZS_APPS)): $(LIBBLAZESYM_OBJ)
$(BZS_APPS): $(LIBBLAZESYM_OBJ)

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(if $(wildcard $*.cpp), \
	    $(CXX) $(CXXFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@, \
	    $(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@)

$(USER_APP): $(USER_APP).c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(USER_APP).c $(ALL_LDFLAGS)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (tmp.bpf.o) targets
.SECONDARY:
