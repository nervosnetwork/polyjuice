# TARGET := riscv64-unknown-linux-gnu
TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
CXX := $(TARGET)-g++
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy

CFLAGS_CKB_STD = -Ideps/ckb-c-stdlib
CFLAGS_INTX := -Ideps/intx/lib/intx -Ideps/intx/include
CFLAGS_ETHASH := -Ideps/ethash/include -Ideps/ethash/lib/ethash -Ideps/ethash/lib/keccak -Ideps/ethash/lib/support
CFLAGS_EVMONE := -Ideps/evmone/lib/evmone -Ideps/evmone/include -Ideps/evmone/evmc/include
CFLAGS_SECP := -isystem deps/secp256k1/src -isystem deps/secp256k1
CFLAGS := -O3 $(CFLAGS_CKB_STD) $(CFLAGS_EVMONE) $(CFLAGS_INTX) $(CFLAGS_ETHASH) $(CFLAGS_SECP) -Wall -g
CXXFLAGS := $(CFLAGS) -std=c++1z
LDFLAGS := -fdata-sections -ffunction-sections -Wl,--gc-sections
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h

ALL_OBJS := build/evmone.o build/analysis.o build/execution.o build/instructions.o build/div.o build/keccak.o build/keccakf800.o build/keccakf1600.o

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
# BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3
# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

all: build/generator build/generator_test build/validator

all-via-docker:
	mkdir -p build
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/validator: vm.c vm_validator.h build/secp256k1_data_info.h $(SECP256K1_SRC) $(ALL_OBJS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ vm.c $(ALL_OBJS)
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/generator: vm.c vm_generator.h $(ALL_OBJS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ vm.c $(ALL_OBJS) -DBUILD_GENERATOR
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/generator_test: vm.c vm_test.h $(ALL_OBJS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ vm.c $(ALL_OBJS) -DBUILD_GENERATOR -DTEST_BIN

build/evmone.o: deps/evmone/lib/evmone/evmone.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $< -DPROJECT_VERSION=\"0.5.0-dev\"
build/analysis.o: deps/evmone/lib/evmone/analysis.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/execution.o: deps/evmone/lib/evmone/execution.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/instructions.o: deps/evmone/lib/evmone/instructions.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<

build/keccak.o: deps/ethash/lib/keccak/keccak.c build/keccakf800.o build/keccakf1600.o
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
build/keccakf1600.o: deps/ethash/lib/keccak/keccakf1600.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
build/keccakf800.o: deps/ethash/lib/keccak/keccakf800.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -c -o $@ $<

build/div.o: deps/intx/lib/intx/div.cpp
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

# secp256k1
build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc $(CFLAGS_SECP) $(CFLAGS_CKB_STD) -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

clean:
	rm -rf build/*
	cd deps/secp256k1 && [ -f "Makefile" ] && make clean

clean-bin:
	rm -rf build/generator_test build/generator build/validator
