ifeq (,$(wildcard config.mk))
	$(error "config.mk not found. run ./configure first")
endif

include config.mk

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
CFLAGS := -Wall -Werror -std=c99 -g -O2 \
          $(MONOCYPHER_CFLAGS) $(BRAID_CFLAGS)
LDFLAGS := $(MONOCYPHER_LDFLAGS) $(BRAID_LDFLAGS)

.PHONY: all clean install test

all: cherf2

cherf2: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_cherf2: tests/test_cherf2.c helpers.o
	$(CC) $(CFLAGS) -Itests -o $@ $^ $(LDFLAGS)

test: tests/test_cherf2
	./tests/test_cherf2

clean:
	rm -f $(OBJS) cherf2 tests/test_cherf2

install: cherf2
	install -d $(PREFIX)/bin
	install -m 755 cherf2 $(PREFIX)/bin/

