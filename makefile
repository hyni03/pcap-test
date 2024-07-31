all: pcap-test

pcap-test.o: pcap-test.cpp
	g++ -c -o pcap-test.o pcap-test.cpp

pcap-test: pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

clean:
	rm -f pcap-test *.o