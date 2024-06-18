CC ?= afl-clang-fast

.PHONY: all clean

all: magicbytes magicbytes_cmplog

magicbytes: magicbytes.c Makefile
	echo "Using compiler: $(CC)"
	$(CC) magicbytes.c -o magicbytes

magicbytes_cmplog: magicbytes.c Makefile
	echo "Using compiler: $(CC)"
	AFL_LLVM_CMPLOG=1 $(CC) magicbytes.c -o magicbytes_cmplog

clean:
	rm magicbytes magicbytes_cmplog
