# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT ?= libdecaf
PROJECT := $(strip $(PROJECT))

C_SRC_DIR ?= $(CURDIR)
C_SRC_ENV ?= $(C_SRC_DIR)/env.mk
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT)
C_SRC_TYPE ?= shared

# System type and C compiler/flags.

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

ifeq ($(PLATFORM),msys2)
	C_SRC_OUTPUT_EXECUTABLE_EXTENSION ?= .exe
	C_SRC_OUTPUT_SHARED_EXTENSION ?= .dll
else
	C_SRC_OUTPUT_EXECUTABLE_EXTENSION ?=
	C_SRC_OUTPUT_SHARED_EXTENSION ?= .so
endif

ifeq ($(C_SRC_TYPE),shared)
	C_SRC_OUTPUT_FILE = $(C_SRC_OUTPUT)$(C_SRC_OUTPUT_SHARED_EXTENSION)
else
	C_SRC_OUTPUT_FILE = $(C_SRC_OUTPUT)$(C_SRC_OUTPUT_EXECUTABLE_EXTENSION)
endif

ifeq ($(PLATFORM),msys2)
# We hardcode the compiler used on MSYS2. The default CC=cc does
# not produce working code. The "gcc" MSYS2 package also doesn't.
	CC = /mingw64/bin/gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),darwin)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -arch x86_64 -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -arch x86_64 -fstack-protector -Wall
	LDFLAGS ?= -arch x86_64 -flat_namespace -undefined suppress
else ifeq ($(PLATFORM),freebsd)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
else ifeq ($(PLATFORM),solaris)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -fstack-protector -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -fstack-protector -Wall
	LDLIBS ?= -lssp
endif

ifneq ($(PLATFORM),msys2)
	CFLAGS += -fPIC
	CXXFLAGS += -fPIC
endif

# FIXME: ARCHFLAGS
ARCHFLAGS ?= -maes -mavx2 -mbmi2
CFLAGS += $(ARCHFLAGS)
CXXFLAGS += $(ARCHFLAGS)

ED448GOLDILOCKS_VSN ?= 61c3379cc95b0699ac44a9402fbccc01bce46d17
ED448GOLDILOCKS_DIR ?= $(BASEDIR)/.ed448goldilocks
ED448GOLDILOCKS_GIT ?= git://github.com/potatosalad/ed448goldilocks.git
ED448GOLDILOCKS_OUTPUT_FILE ?= $(ED448GOLDILOCKS_DIR)/build/lib/libdecaf.so.1
ED448GOLDILOCKS_OBJECTS ?= $(ED448GOLDILOCKS_DIR)/build/obj/curve25519/crypto.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/curve25519/decaf.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/curve25519/decaf_tables.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/curve25519/eddsa.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/curve25519/elligator.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/curve25519/scalar.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/ed448goldilocks/crypto.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/ed448goldilocks/decaf.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/ed448goldilocks/decaf_tables.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/ed448goldilocks/eddsa.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/ed448goldilocks/elligator.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/ed448goldilocks/scalar.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/p25519/f_arithmetic.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/p25519/f_generic.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/p25519/f_impl.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/p448/f_arithmetic.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/p448/f_generic.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/p448/f_impl.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/sha512.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/shake.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/strobe.o	\
	$(ED448GOLDILOCKS_DIR)/build/obj/utils.o

CFLAGS += -I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" -I"$(ED448GOLDILOCKS_DIR)/src/GENERATED/include"
CXXFLAGS += -I"$(ERTS_INCLUDE_DIR)" -I"$(ERL_INTERFACE_INCLUDE_DIR)" -I"$(ED448GOLDILOCKS_DIR)/src/GENERATED/include"

LDLIBS += -L"$(ERL_INTERFACE_LIB_DIR)" -lerl_interface -lei $(ED448GOLDILOCKS_OBJECTS)

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

ifeq ($(SOURCES),)
	SOURCES := $(sort $(foreach pat,*.c *.C *.cc *.cpp,$(call core_find,$(C_SRC_DIR)/,$(pat))))
endif
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

all:: deps app

app:: $(C_SRC_OUTPUT_FILE)

ifneq ($(wildcard $(ED448GOLDILOCKS_OUTPUT_FILE)),)

deps::

else

deps:: $(ED448GOLDILOCKS_OUTPUT_FILE)

endif

$(ED448GOLDILOCKS_DIR):
	$(verbose) git clone -n $(ED448GOLDILOCKS_GIT) $(ED448GOLDILOCKS_DIR)
	$(verbose) (cd $(ED448GOLDILOCKS_DIR) && git checkout -q $(ED448GOLDILOCKS_VSN))

$(ED448GOLDILOCKS_OUTPUT_FILE): $(ED448GOLDILOCKS_DIR)
	$(verbose) $(MAKE) -C $(ED448GOLDILOCKS_DIR) lib

test-build:: $(C_SRC_OUTPUT_FILE)

$(C_SRC_OUTPUT_FILE): $(OBJECTS)
	$(verbose) mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) $(OBJECTS) \
		$(LDFLAGS) $(if $(filter $(C_SRC_TYPE),shared),-shared) $(LDLIBS) \
		-o $(C_SRC_OUTPUT_FILE)

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
	$(gen_verbose) rm -f $(C_SRC_OUTPUT_FILE) $(OBJECTS)

ifneq ($(wildcard $(C_SRC_ENV)),)
-include $(C_SRC_ENV)
else
ERTS_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)]).")
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)]).")
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)]).")
endif
