all: test

test: test.c
	gcc -o pcap_test test.c -lpcap

clean:
	rm -rf pcap_test
