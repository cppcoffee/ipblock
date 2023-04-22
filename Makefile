.PHONY: clean all

all: libbpf
	$(MAKE) -C ./src

libbpf:
	BUILD_STATIC_ONLY=y PREFIX=/opt/libbpf $(MAKE) -C ./libbpf/src install

clean:
	$(MAKE) -C ./src clean
	$(MAKE) -C ./libbpf/src clean

