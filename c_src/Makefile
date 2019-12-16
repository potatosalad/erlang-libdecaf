# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT = libdecaf

# Configuration.

C_SRC_DIR ?= $(CURDIR)
C_SRC_ENV ?= $(C_SRC_DIR)/env.mk
C_SRC_NIF ?= $(BASEDIR)/priv/$(PROJECT)_nif

C_DEPS_DIR ?= $(BASEDIR)/c_deps

# "erl" command.

ERL = erl +A0 -noinput -boot start_clean

# Platform detection.

ifeq ($(PLATFORM),)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
PLATFORM = linux
else ifeq ($(UNAME_S),Darwin)
PLATFORM = darwin
else ifeq ($(UNAME_S),SunOS)
PLATFORM = solaris
else ifeq ($(UNAME_S),GNU)
PLATFORM = gnu
else ifeq ($(UNAME_S),FreeBSD)
PLATFORM = freebsd
else ifeq ($(UNAME_S),NetBSD)
PLATFORM = netbsd
else ifeq ($(UNAME_S),OpenBSD)
PLATFORM = openbsd
else ifeq ($(UNAME_S),DragonFly)
PLATFORM = dragonfly
else ifeq ($(shell uname -o),Msys)
PLATFORM = msys2
else
$(error Unable to detect platform. Please open a ticket with the output of uname -a.)
endif

export PLATFORM
endif

# System type and C compiler/flags.

ifeq ($(PLATFORM),msys2)
	C_SRC_EXECUTABLE_EXTENSION ?= .exe
	C_SRC_SHARED_EXTENSION ?= .dll
else
	C_SRC_EXECUTABLE_EXTENSION ?=
	C_SRC_SHARED_EXTENSION ?= .so
endif

C_SRC_NIF_FILE = $(C_SRC_NIF)$(C_SRC_SHARED_EXTENSION)

ifeq ($(PLATFORM),msys2)
# We hardcode the compiler used on MSYS2. The default CC=cc does
# not produce working code. The "gcc" MSYS2 package also doesn't.
	CC = /mingw64/bin/gcc
	CFLAGS ?= -O3 -std=c11 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -std=c++11 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),darwin)
	CC ?= cc
	CFLAGS ?= -O3 -std=c11 -arch x86_64 -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -std=c++11 -arch x86_64 -fstack-protector -Wall
	LDFLAGS ?= -arch x86_64 -flat_namespace -undefined suppress
else ifeq ($(PLATFORM),freebsd)
	CC ?= cc
	CFLAGS ?= -O3 -std=c11 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -std=c++11 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c11 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -std=c++11 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),solaris)
	CC ?= cc
	CFLAGS ?= -O3 -std=c11 -finline-functions -fstack-protector -Wall -Wmissing-prototypes -fPIC
	CXXFLAGS ?= -O3 -std=c++11 -finline-functions -fstack-protector -Wall -fPIC
	LDLIBS ?= -latomic -lssp
endif

ifneq ($(PLATFORM),msys2)
	CFLAGS += -fPIC
	CXXFLAGS += -fPIC
endif

ifneq ($(CROSSCOMPILER),)
	CC = $(CROSSCOMPILER)gcc
endif

CFLAGS += -I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" -I"$(ED448GOLDILOCKS_INCLUDE_DIR)"
CXXFLAGS += -I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" -I"$(ED448GOLDILOCKS_INCLUDE_DIR)"

LDLIBS += -L"$(ERL_INTERFACE_LIB_DIR)" \
	-lerl_interface \
	-lei \
	$(ED448GOLDILOCKS_OBJECTS)

# Dependencies.

ED448GOLDILOCKS_VSN ?= v1.0
ED448GOLDILOCKS_GIT ?= https://github.com/potatosalad/ed448goldilocks.git
ED448GOLDILOCKS_SRC_DIR ?= $(C_DEPS_DIR)/ed448goldilocks
ED448GOLDILOCKS_OUTPUT_FILE ?= $(ED448GOLDILOCKS_SRC_DIR)/build/lib/libdecaf.so.1
ED448GOLDILOCKS_LIB_DIR ?= $(ED448GOLDILOCKS_SRC_DIR)/src/GENERATED/include
ED448GOLDILOCKS_INCLUDE_DIR ?= $(ED448GOLDILOCKS_SRC_DIR)/src/GENERATED/include
ED448GOLDILOCKS_MAKE_FILE ?= $(ED448GOLDILOCKS_SRC_DIR)/Makefile
ED448GOLDILOCKS_OBJECTS ?= $(ED448GOLDILOCKS_SRC_DIR)/build/obj/curve25519/decaf.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/curve25519/decaf_tables.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/curve25519/eddsa.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/curve25519/elligator.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/curve25519/scalar.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/ed448goldilocks/decaf.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/ed448goldilocks/decaf_tables.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/ed448goldilocks/eddsa.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/ed448goldilocks/elligator.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/ed448goldilocks/scalar.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/p25519/f_arithmetic.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/p25519/f_generic.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/p25519/f_impl.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/p448/f_arithmetic.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/p448/f_generic.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/p448/f_impl.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/sha512.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/shake.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/spongerng.o	\
	$(ED448GOLDILOCKS_SRC_DIR)/build/obj/utils.o

ALL_DEPS_OUTPUT ?= $(ED448GOLDILOCKS_OUTPUT_FILE)

# Verbosity.

V ?= 0

verbose_0 = @
verbose_2 = set -x;
verbose = $(verbose_$(V))

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))

dep_verbose_0 = @echo " DEP   " $(1);
dep_verbose_2 = set -x;
dep_verbose = $(dep_verbose_$(V))

gen_verbose_0 = @echo " GEN   " $@;
gen_verbose_2 = set -x;
gen_verbose = $(gen_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

# Targets.

core_find = $(if $(wildcard $1),$(shell find $(1:%/=%) -type f -name $(subst *,\*,$2)))

ifeq ($(PLATFORM),msys2)
core_native_path = $(subst \,\\\\,$(shell cygpath -w $1))
else
core_native_path = $1
endif

ifeq ($(NIF_SOURCES),)
NIF_SOURCES := $(sort $(foreach pat,*.c *.C *.cc *.cpp,$(call core_find,$(C_SRC_DIR)/nif/,$(pat))))
endif
NIF_OBJECTS = $(addsuffix .o, $(basename $(NIF_SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

all:: deps app

app:: $(C_SRC_ENV) $(C_SRC_NIF_FILE)

ifeq ($(filter $(foreach p,$(ALL_DEPS_OUTPUT),$(if $(wildcard $(p)),,x)), x),)

deps::

else

deps:: $(ED448GOLDILOCKS_OUTPUT_FILE)

endif

test-build:: $(C_SRC_ENV) $(C_SRC_NIF_FILE)

$(C_DEPS_DIR):
	$(verbose) mkdir -p $(C_DEPS_DIR)

$(ED448GOLDILOCKS_SRC_DIR):
	$(verbose) if [ ! -f $(ED448GOLDILOCKS_SRC_DIR)/configure ]; then \
		git clone -n $(ED448GOLDILOCKS_GIT) $(ED448GOLDILOCKS_SRC_DIR) && \
		(cd $(ED448GOLDILOCKS_SRC_DIR) && git checkout -q $(ED448GOLDILOCKS_VSN)); \
	else \
		true; \
	fi

$(ED448GOLDILOCKS_OUTPUT_FILE): $(ED448GOLDILOCKS_SRC_DIR)
	$(MAKE) -C $(ED448GOLDILOCKS_SRC_DIR) lib

$(C_SRC_NIF_FILE): $(NIF_OBJECTS)
	$(verbose) mkdir -p $(BASEDIR)/priv
	$(link_verbose) $(CC) $(NIF_OBJECTS) \
		$(LDFLAGS) -shared $(LDLIBS) \
		-o $(C_SRC_NIF_FILE)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:: clean-c_src

clean-c_src:
	$(gen_verbose) rm -f $(C_SRC_NIF_FILE) $(NIF_OBJECTS)

$(C_SRC_ENV):
	$(verbose) $(ERL) -eval "file:write_file(\"$(call core_native_path,$(C_SRC_ENV))\", \
		io_lib:format( \
			\"ERTS_INCLUDE_DIR ?= ~s/erts-~s/include/~n\" \
			\"ERL_INTERFACE_INCLUDE_DIR ?= ~s~n\" \
			\"ERL_INTERFACE_LIB_DIR ?= ~s~n\", \
			[code:root_dir(), erlang:system_info(version), \
			code:lib_dir(erl_interface, include), \
			code:lib_dir(erl_interface, lib)])), \
		halt()."

distclean:: distclean-deps distclean-env

distclean-deps:
	$(gen_verbose) rm -rf $(C_DEPS_DIR)

distclean-env:
	$(gen_verbose) rm -f $(C_SRC_ENV)

format:
	$(gen_verbose) clang-format -i nif/*.c nif/*.h nif/impl/*.c.h

-include $(C_SRC_ENV)
