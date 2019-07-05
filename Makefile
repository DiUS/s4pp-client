CFLAGS=-std=c99 -Wall -Wextra -O2 -g -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L -DECB=0 -DCTR=0
LDFLAGS=

SRCS=\
	s4pp.c \
	digests.c \
	main.c \
	sha2.c \
	tiny-AES-c/aes.c \

sha2.o: CFLAGS+=-fno-strict-aliasing

OBJS=$(SRCS:.c=.o)

s4ppc: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@


.PHONY: clean
clean:
	-rm -f s4ppc *.o tiny-AES-c/aes.o
