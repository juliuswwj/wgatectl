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
  src/seen_db.c      \
  src/ipset_mgr.c    \
  src/iptables.c     \
  src/arp_bind.c     \
  src/sniffer.c      \
  src/metrics.c      \
  src/ipc.c          \
  src/schedule.c     \
  src/filterd.c      \
  src/pins.c         \
  src/dnsmasq_conf.c \
  src/json.c

OBJ := $(SRC:.c=.o)
DEP := $(OBJ:.o=.d)

BIN := wgatectl

# Object files that the unit tests need (everything that schedule/supervisor
# touch except main.c, sniffer.c, ipc.c — those pull in epoll/libpcap and are
# orthogonal to the logic under test).
TEST_CORE_OBJ := \
  src/config.o      \
  src/log.o         \
  src/util.o        \
  src/jsonl.o       \
  src/leases.o      \
  src/seen_db.o     \
  src/ipset_mgr.o   \
  src/iptables.o    \
  src/arp_bind.o    \
  src/metrics.o     \
  src/schedule.o    \
  src/filterd.o     \
  src/pins.o        \
  src/dnsmasq_conf.o \
  src/json.o

TEST_BINS := tests/test_schedule tests/test_pins tests/test_filterd tests/test_dnsmasq_conf tests/test_seen_db

.PHONY: all clean install asan test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

tests/test_schedule: tests/test_schedule.c $(TEST_CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_CORE_OBJ) $(LDFLAGS) $(LDLIBS)

tests/test_pins: tests/test_pins.c $(TEST_CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_CORE_OBJ) $(LDFLAGS) $(LDLIBS)

tests/test_filterd: tests/test_filterd.c $(TEST_CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_CORE_OBJ) $(LDFLAGS) $(LDLIBS)

tests/test_dnsmasq_conf: tests/test_dnsmasq_conf.c $(TEST_CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_CORE_OBJ) $(LDFLAGS) $(LDLIBS)

tests/test_seen_db: tests/test_seen_db.c $(TEST_CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_CORE_OBJ) $(LDFLAGS) $(LDLIBS)

asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -std=c11 -D_GNU_SOURCE $(WARN) $(PCAP_CFLAGS) -Iinclude" \
	        LDFLAGS="-fsanitize=address,undefined" \
	        all $(TEST_BINS)

test: $(TEST_BINS)
	tests/test_schedule
	tests/test_pins
	tests/test_filterd
	tests/test_dnsmasq_conf
	tests/test_seen_db

install: $(BIN)
	install -d $(DESTDIR)$(SBINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(SBINDIR)/$(BIN)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 systemd/wgatectl.service $(DESTDIR)$(UNITDIR)/wgatectl.service
ifeq ($(DESTDIR),)
	systemctl daemon-reload
	systemctl restart wgatectl
endif

clean:
	rm -f $(OBJ) $(DEP) $(BIN) $(TEST_BINS)

-include $(DEP)
