.PHONY: dnsd
.DEFAULT_GOAL := dnsd

COMPILER_CXX = c++
CXX_FLAGS = -std=c++14 -O2 -g
LD_FLAGS = -lpthread

dnsd:
	$(COMPILER_CXX) $(CXX_FLAGS) -I./include src/main.cc src/dnsd.cc src/message.cc src/debug.cc -o dnsd $(LD_FLAGS)

check:
	$(COMPILER_CXX) -std=c++14 -O0 -g -I./include test/test.cc src/dnsd.cc src/message.cc src/debug.cc -o unittest $(LD_FLAGS)
	./unittest -s

clean:
	rm -f ./unittest ./dnsd