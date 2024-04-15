LDLIBS=-lpcap

all: arp-spoof


main.o: mac.h ip.h ethhdr.h arphdr.h util.h attack.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

util.o: util.h util.cpp

attack.o: attack.h attack.cpp

arp-spoof: main.o arphdr.o ethhdr.o iphdr.o ip.o mac.o util.o attack.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
