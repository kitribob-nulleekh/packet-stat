LDLIBS=-lpcap

all: packet-stat

packet-stat: main.o ethhdr.o ip.o iphdr.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm *.o packet-stat