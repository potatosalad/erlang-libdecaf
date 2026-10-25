# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT = libdecaf

# Configuration.

C_SRC_DIR ?= $(CURDIR)
C_SRC_ENV ?= $(C_SRC_DIR)/env.mk
C_SRC_OUTPUT ?= $(BASEDIR)/priv/$(PROJECT)_nif
C_SRC_TYPE ?= shared

C_DEPS_DIR ?= $(BASEDIR)/c_deps

SANITIZE ?= 0
CFLAGS_SANITIZE ?= -O1 -fsanitize=address,undefined -fno-common -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-sanitize-recover=all
CXXFLAGS_SANITIZE ?= $(CFLAGS_SANITIZE)
LDFLAGS_SANITIZE ?= -fsanitize=address,undefined
ED448GOLDILOCKS_TESTS ?= OFF

# "erl" command.

ERL_CMD ?= erl
ERL = $(ERL_CMD) +A1 -noinput -boot no_dot_erlang

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

CFLAGS_COMMON ?= \
-O2 \
-g \
-ggdb \
-std=c2x \
-finline-functions \
-fno-omit-frame-pointer \
-D_GNU_SOURCE \
-D_REENTRANT

CXXFLAGS_COMMON ?= \
-O2 \
-g \
-ggdb \
-std=c++20 \
-finline-functions \
-fno-omit-frame-pointer \
-D_GLIBCXX_RESTRICT_EXCEPTIONS \
-D_GNU_SOURCE \
-D_REENTRANT

ifeq ($(PLATFORM),msys2)
# We hardcode the compiler used on MSYS2. The default CC=cc does
# not produce working code. The "gcc" MSYS2 package also doesn't.
	CC = /mingw64/bin/gcc
	export CC
	CXX = /mingw64/bin/g++
	export CXX
	CFLAGS ?= $(CFLAGS_COMMON) -Wall
	CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
else
# Determine whether `clang` is available
	CLANG_AVAILABLE := $(shell command -v clang >/dev/null 2>&1 && echo yes)
	ifneq ($(CLANG_AVAILABLE),)
		CC ?= clang
		CXX ?= clang++
	else ifeq ($(PLATFORM),linux)
		CC ?= gcc
		CXX ?= g++
	else
		CC ?= cc
		CXX ?= c++
	endif
	ifeq ($(PLATFORM),darwin)
		CFLAGS ?= $(CFLAGS_COMMON) -Wall
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
		LDFLAGS ?= -flat_namespace -undefined dynamic_lookup
	else ifeq ($(PLATFORM),freebsd)
		CFLAGS ?= $(CFLAGS_COMMON) -Wall
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
	else ifeq ($(PLATFORM),linux)
		CFLAGS ?= $(CFLAGS_COMMON) -Wall
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -Wall
	else ifeq ($(PLATFORM),solaris)
		CFLAGS ?= $(CFLAGS_COMMON) -fstack-protector
		CXXFLAGS ?= $(CXXFLAGS_COMMON) -fstack-protector
	endif
endif

ifneq ($(PLATFORM),msys2)
	CFLAGS += -fPIC
	CXXFLAGS += -fPIC
endif

ifneq ($(CROSSCOMPILER),)
	CC = $(CROSSCOMPILER)gcc
	CXX = $(CROSSCOMPILER)g++
endif

ifeq ($(SANITIZE),1)
	CFLAGS += $(CFLAGS_SANITIZE)
	CXXFLAGS += $(CXXFLAGS_SANITIZE)
	LDFLAGS += $(LDFLAGS_SANITIZE)
endif

CFLAGS += \
	-I"$(ERTS_INCLUDE_DIR)" \
	-I"$(ERL_INTERFACE_INCLUDE_DIR)" \
	-I"$(ED448GOLDILOCKS_INCLUDE_DIR)" \
	-I"$(ED448GOLDILOCKS_SRC_DIR)/src/include"
CXXFLAGS += \
	-I"$(ERTS_INCLUDE_DIR)" \
	-I"$(ERL_INTERFACE_INCLUDE_DIR)" \
	-I"$(ED448GOLDILOCKS_INCLUDE_DIR)" \
	-I"$(ED448GOLDILOCKS_SRC_DIR)/src/include"

LDLIBS += -L"$(ERL_INTERFACE_LIB_DIR)" \
	"$(ED448GOLDILOCKS_OUTPUT_FILE)"

# Dependencies.

ED448GOLDILOCKS_VSN ?= features-20261025-v1.0.5
ED448GOLDILOCKS_GIT ?= https://github.com/potatosalad/ed448goldilocks.git
ED448GOLDILOCKS_SRC_DIR ?= $(C_DEPS_DIR)/ed448goldilocks
ED448GOLDILOCKS_BUILD_DIR ?= $(C_DEPS_DIR)/ed448goldilocks-build$(if $(filter 1,$(SANITIZE)),-sanitizers)
ED448GOLDILOCKS_INCLUDE_DIR ?= $(ED448GOLDILOCKS_BUILD_DIR)/src/GENERATED/include
ED448GOLDILOCKS_LIB_DIR ?= $(ED448GOLDILOCKS_BUILD_DIR)/src
ED448GOLDILOCKS_OUTPUT_FILE ?= $(ED448GOLDILOCKS_BUILD_DIR)/src/libdecaf.a
ED448GOLDILOCKS_MAKE_FILE ?= $(ED448GOLDILOCKS_BUILD_DIR)/Makefile

ALL_DEPS_OUTPUT ?= $(ED448GOLDILOCKS_OUTPUT_FILE)

# Verbosity.

V ?= 0

verbose_0 = @
verbose_2 = set -x;
verbose = $(verbose_$(V))

ifeq ($(V),3)
SHELL := $(SHELL) -x
endif

gen_verbose_0 = @echo " GEN   " $@;
gen_verbose_2 = set -x;
gen_verbose = $(gen_verbose_$(V))

gen_verbose_esc_0 = @echo " GEN   " $$@;
gen_verbose_esc_2 = set -x;
gen_verbose_esc = $(gen_verbose_esc_$(V))

c_verbose_0 = @echo " C     " $(filter-out $(notdir $(MAKEFILE_LIST) $(C_SRC_ENV)),$(^F));
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(filter-out $(notdir $(MAKEFILE_LIST) $(C_SRC_ENV)),$(^F));
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

# Targets.

ifeq ($(PLATFORM),msys2)
core_native_path = $(shell cygpath -m $1)
else
core_native_path = $1
endif

# We skip files that contain spaces because they end up causing issues.
core_find = $(if $(wildcard $1),$(shell find $(1:%/=%) \( -type l -o -type f \) -name $(subst *,\*,$2) | grep -v " "))

ifeq ($(SOURCES),)
SOURCES := $(sort $(foreach pat,*.c *.C *.cc *.cpp,$(call core_find,$(C_SRC_DIR)/nif/,$(pat))))
endif
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))
DEPFILES = $(OBJECTS:.o=.d)

ifeq ($(FORMAT_NIF_SOURCES),)
FORMAT_NIF_SOURCES := $(shell find $(C_SRC_DIR)/nif \( -type l -o -type f \) \( -name '*.c' -o -name '*.C' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.c.h' -o -name '*.hpp' \) | grep -v " ")
endif

ifeq ($(FORMAT_PRIMITIVE_SOURCES),)
FORMAT_PRIMITIVE_SOURCES := $(shell find $(C_SRC_DIR)/primitive \( -type l -o -type f \) \( -name '*.c' -o -name '*.C' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.c.h' -o -name '*.hpp' \) | grep -v " ")
endif

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -MP -MF $(@:.o=.d) -MT $@ -c

all:: deps app

app:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

deps:: $(ALL_DEPS_OUTPUT)

test-build:: $(C_SRC_ENV) $(C_SRC_OUTPUT_FILE)

$(C_DEPS_DIR):
	$(verbose) mkdir -p $(C_DEPS_DIR)

$(ED448GOLDILOCKS_SRC_DIR)/CMakeLists.txt: | $(C_DEPS_DIR)
	$(verbose) if [ ! -f $(ED448GOLDILOCKS_SRC_DIR)/CMakeLists.txt ]; then \
		git clone -n $(ED448GOLDILOCKS_GIT) $(ED448GOLDILOCKS_SRC_DIR) && \
		(cd $(ED448GOLDILOCKS_SRC_DIR) && git checkout -q $(ED448GOLDILOCKS_VSN)) && \
		patch -d "$(ED448GOLDILOCKS_SRC_DIR)" -p1 < "$(C_SRC_DIR)/patches/ed448goldilocks-empty-buffers.patch"; \
	else \
		true; \
	fi

$(ED448GOLDILOCKS_MAKE_FILE): $(ED448GOLDILOCKS_SRC_DIR)/CMakeLists.txt $(C_SRC_DIR)/Makefile
	$(verbose) mkdir -p $(ED448GOLDILOCKS_BUILD_DIR)
	$(verbose) cd $(ED448GOLDILOCKS_BUILD_DIR) && cmake \
			-DCMAKE_C_COMPILER="$(CC)" \
			-DCMAKE_CXX_COMPILER="$(CXX)" \
			-DENABLE_SHARED=OFF \
			-DENABLE_STATIC=ON \
			-DENABLE_STRICT=OFF \
			-DENABLE_TESTS=$(ED448GOLDILOCKS_TESTS) \
			-DENABLE_SANITIZER=$(if $(filter 1,$(SANITIZE)),ON,OFF) \
			-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
			-DCMAKE_C_FLAGS="-fPIC -g $(if $(filter 1,$(SANITIZE)),$(CFLAGS_SANITIZE))" \
			-DCMAKE_CXX_FLAGS="-fPIC -g $(if $(filter 1,$(SANITIZE)),$(CXXFLAGS_SANITIZE))" \
			"$(ED448GOLDILOCKS_SRC_DIR)"

# Revisit CMake's dependency graph when bundled source or backend files change.
$(ED448GOLDILOCKS_OUTPUT_FILE): $(ED448GOLDILOCKS_MAKE_FILE) $(call core_find,$(ED448GOLDILOCKS_SRC_DIR)/src/,*)
	$(MAKE) -C $(ED448GOLDILOCKS_BUILD_DIR)
	$(verbose) touch $@

$(C_SRC_OUTPUT_FILE): $(ALL_DEPS_OUTPUT) $(OBJECTS)
	$(verbose) mkdir -p $(dir $@)
	$(link_verbose) $(CC) $(OBJECTS) \
		$(LDFLAGS) $(if $(filter $(C_SRC_TYPE),shared),-shared) $(LDLIBS) \
		-o $(C_SRC_OUTPUT_FILE)

$(OBJECTS): $(MAKEFILE_LIST) $(C_SRC_ENV) | $(ALL_DEPS_OUTPUT)

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
	$(gen_verbose) rm -f $(C_SRC_OUTPUT_FILE) $(OBJECTS) $(DEPFILES)

distclean:: distclean-c_src-env distclean-deps

distclean-c_src-env:
	$(gen_verbose) rm -f $(C_SRC_ENV)

distclean-deps:
	$(gen_verbose) rm -rf $(C_DEPS_DIR)

format:
	$(gen_verbose) clang-format -i $(FORMAT_NIF_SOURCES) $(FORMAT_PRIMITIVE_SOURCES)

lint-format:
	$(gen_verbose) clang-format --dry-run --Werror $(FORMAT_NIF_SOURCES) $(FORMAT_PRIMITIVE_SOURCES)

ifneq ($(wildcard $(C_SRC_DIR)),)
ERL_ERTS_DIR = $(shell $(ERL) -eval 'io:format("~s~n", [code:lib_dir(erts)]), halt().')

$(C_SRC_ENV):
	$(verbose) $(ERL) -eval "file:write_file(\"$(call core_native_path,$(C_SRC_ENV))\", \
		io_lib:format( \
			\"# Generated by Erlang.mk. Edit at your own risk!~n~n\" \
			\"ERTS_INCLUDE_DIR ?= ~s/erts-~s/include/~n\" \
			\"ERL_INTERFACE_INCLUDE_DIR ?= ~s~n\" \
			\"ERL_INTERFACE_LIB_DIR ?= ~s~n\" \
			\"ERTS_DIR ?= $(ERL_ERTS_DIR)~n\" \
			\"ERTS_BIN_DIR ?= ~s/erts-~s/bin~n\", \
			[code:root_dir(), erlang:system_info(version), \
			code:lib_dir(erl_interface, include), \
			code:lib_dir(erl_interface, lib), \
			code:root_dir(), erlang:system_info(version)])), \
		halt()."

-include $(C_SRC_ENV)

ifneq ($(ERL_ERTS_DIR),$(ERTS_DIR))
$(shell rm -f $(C_SRC_ENV))
endif

-include $(DEPFILES)
endif

.PHONY: test-spongerng

test-spongerng: $(ED448GOLDILOCKS_OUTPUT_FILE)
	$(verbose) mkdir -p "$(BASEDIR)/logs/native"
	$(verbose) $(CC) $(CFLAGS) $(CPPFLAGS) "$(BASEDIR)/test/native/spongerng.c" \
		"$(ED448GOLDILOCKS_OUTPUT_FILE)" -o "$(BASEDIR)/logs/native/spongerng"
	$(verbose) "$(BASEDIR)/logs/native/spongerng"
