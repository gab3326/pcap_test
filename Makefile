all: pcap_test

pcap_test: test.c
	gcc -p pcap_test test.c -lpcap

clean:
	rm -rf pcap_test
