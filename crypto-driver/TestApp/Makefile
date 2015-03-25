.PHONY: all
CC:= $(CROSS_COMPILE)gcc
CFLAGS:= -O2 -Wall -I./ -I../
LIBS:=
all: testctcrypto

testctcrypto: testctcrypto.o
	@$(CC) $(LIBS) -o $@ $<
testctcrypto.o: testctcrypto.c
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
    rm -f *.o
	rm -f testctcrypto
