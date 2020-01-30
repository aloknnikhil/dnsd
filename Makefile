.PHONY: dnsd
.DEFAULT_GOAL := dnsd

COMPILER_CXX = c++
CXX_FLAGS = -std=c++14 -O2 -g
LD_FLAGS = -lpthread

dnsd:
	$(COMPILER_CXX) $(CXX_FLAGS) main.cc dnsd.cc message.cc debug.cc -o dnsd $(LD_FLAGS)

check:
	$(COMPILER_CXX) $(CXX_FLAGS) test.cc dnsd.cc -o test $(LD_FLAGS)
	./test -s

clean:
	rm -f ./test ./dnsd