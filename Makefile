.PHONY: dnsd
.DEFAULT_GOAL := dnsd

COMPILER_CXX = clang++
CXX_FLAGS = -std=c++17 -O2 -g

dnsd:
	$(COMPILER_CXX) $(CXX_FLAGS) main.cc dnsd.cc -o dnsd