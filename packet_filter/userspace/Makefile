CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -lpthread -lm

TARGETS = filter_ctl filter_stats filter_test packet_gen benchmark

all: $(TARGETS)

filter_ctl: filter_ctl.o
	$(CC) -o $@ $^ $(LDFLAGS)

filter_stats: filter_stats.o
	$(CC) -o $@ $^ $(LDFLAGS)

filter_test: filter_test.o
	$(CC) -o $@ $^ $(LDFLAGS)

packet_gen: packet_generator.o
	$(CC) -o $@ $^ $(LDFLAGS) -lpcap

benchmark: benchmark.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c libfilter.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) *.o

install: all
	sudo cp filter_ctl filter_stats /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/filter_ctl /usr/local/bin/filter_stats

.PHONY: all clean install uninstall
