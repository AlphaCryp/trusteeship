TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
GMP := /tmp/gmp
PBC := /tmp/pbc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -O3 -Ideps/molecule -I$(GMP)/include -I$(PBC)/include/pbc -I c -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -L$(PBC)/lib -L$(GMP)/lib -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
MOLC := moleculec
MOLC_VERSION := 0.4.1
PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

all: specs/cells/bls

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/bls: c/bls.c ${PROTOCOL_HEADER} c/common.h c/utils.h pbc
	$(CC) $(CFLAGS) -lpbc -lgmp $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

gmp:
	cd deps/gmp && CC=$(CC) LD=$(LD) ./configure --disable-shared --enable-static --prefix=$(GMP) --host=$(TARGET) && make && make install

pbc: gmp
	cd deps/pbc && CPPFLAGS=-I$(GMP)/include LDFLAGS=-L$(GMP)/lib CC=$(CC) LD=$(LD) ./configure --disable-shared --enable-static --prefix=$(PBC) --host=$(TARGET) && make && make install

generate-protocol: check-moleculec-version ${PROTOCOL_HEADER}

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

package-clean:
	git checkout Cargo.toml Cargo.lock
	rm -rf Cargo.toml.bak target/package/

clean:
	rm -rf build/*.debug
	cd deps/gmp && [ -f "Makefile" ] && make clean
	cd deps/pbc && [ -f "Makefile" ] && make clean
	cd bls && cargo clean

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
