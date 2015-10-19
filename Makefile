CFLAGS=-std=c99 -Wall -Wextra -O2 -g -D_POSIX_SOURCE
LDFLAGS=

SRCS=\
	s4pp.c \
	digests.c \
	main.c \
	sha2.c \

sha2.o: CFLAGS+=-fno-strict-aliasing

OBJS=$(SRCS:.c=.o)

s4ppc: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@


.PHONY: clean
clean:
	-rm -f s4ppc *.o
