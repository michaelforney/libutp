lrt:=$(shell echo "int main() {}"|gcc -x c - -lrt 2>&1)

ifeq ($(lrt),)
  libs:=-lrt
else
  libs:=
endif

utp:=../utp.c ../utp_utils.c
cflags:=-fno-exceptions -fno-rtti

utp_test: utp_test.cpp
	g++ -Wall -o utp_test -g utp_test.cpp $(utp) -DPOSIX -I . -I .. $(libs) $(cflags)
