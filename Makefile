# wgatectl — NanoPi R5C LAN monitor & access-control daemon

PREFIX      ?= /usr/local
SBINDIR     ?= $(PREFIX)/sbin
SYSCONFDIR  ?= /etc
UNITDIR     ?= /etc/systemd/system

CC          ?= cc
PKGCONFIG   ?= pkg-config

PCAP_CFLAGS := $(shell $(PKGCONFIG) --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell $(PKGCONFIG) --libs   libpcap 2>/dev/null)
ifeq ($(strip $(PCAP_LIBS)),)
PCAP_LIBS   := -lpcap
endif

WARN   := -Wall -Wextra -Wshadow -Wpointer-arith -Wformat=2 -Wstrict-prototypes \
          -Wmissing-prototypes -Wold-style-definition -Wvla -Wno-unused-parameter
CFLAGS ?= -O2 -g -fno-omit-frame-pointer
CFLAGS += -std=c11 -D_GNU_SOURCE $(WARN) $(PCAP_CFLAGS) -Iinclude
LDFLAGS ?=
LDLIBS  := $(PCAP_LIBS)

SRC := \
  src/main.c         \
  src/config.c       \
  src/log.c          \
  src/util.c         \
  src/jsonl.c        \
  src/leases.c       \
  src/blocks.c       \
  src/ipset_mgr.c    \
  src/iptables.c     \
  src/sniffer.c      \
  src/metrics.c      \
  src/ipc.c          \
  src/json.c

OBJ := $(SRC:.c=.o)
DEP := $(OBJ:.o=.d)

BIN := wgatectl

.PHONY: all clean install asan test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -std=c11 -D_GNU_SOURCE $(WARN) $(PCAP_CFLAGS) -Iinclude" \
	        LDFLAGS="-fsanitize=address,undefined" \
	        all

test: $(BIN)
	@echo "(no automated tests wired yet — see tests/ for harnesses)"

install: $(BIN)
	install -d $(DESTDIR)$(SBINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(SBINDIR)/$(BIN)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 systemd/wgatectl.service $(DESTDIR)$(UNITDIR)/wgatectl.service
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -m 0644 examples/wgatectl.conf.example $(DESTDIR)$(SYSCONFDIR)/wgatectl.conf.example
	install -d $(DESTDIR)/opt/wgatectl
ifeq ($(DESTDIR),)
	systemctl daemon-reload
	systemctl restart wgatectl
endif

clean:
	rm -f $(OBJ) $(DEP) $(BIN)

-include $(DEP)
