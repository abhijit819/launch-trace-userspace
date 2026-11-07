CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -std=c11
LDFLAGS ?=

.PHONY: all clean install
all: launchtraced

launchtraced: launchtraced.c launchtrace_uapi.h
	$(CC) $(CFLAGS) -o $@ launchtraced.c $(LDFLAGS)

clean:
	rm -f launchtraced

install: launchtraced
	install -D -m 0755 launchtraced $(DESTDIR)/usr/sbin/launchtraced
	install -d -m 0700 $(DESTDIR)/var/lib/launchtrace
