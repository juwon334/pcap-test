#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6
#include "pcap-test.h"

void print_mac(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ip(struct in_addr addr) {
	printf("%s", inet_ntoa(addr));
}

void print_tcp(u_int16_t m){
	printf("%u",ntohs(m));
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void eth(struct libnet_ethernet_hdr *eth_hdr){
	printf("source mac : ");
	print_mac(eth_hdr->ether_shost);
	printf("\n");
	printf("dest mac : ");
	print_mac(eth_hdr->ether_dhost);
	printf("\n");
}

void iph(struct libnet_ipv4_hdr *ipv4hdr){
	printf("source ip : ");
	print_ip(ipv4hdr->ip_src);
	printf("\n");
	printf("dest ip : ");
	print_ip(ipv4hdr->ip_dst);
	printf("\n");	
}

void tcph(struct libnet_tcp_hdr *tcphdr){
	printf("source port : ");
	print_tcp(tcphdr -> th_sport);
	printf("\n");
	printf("dest port : ");
	print_tcp(tcphdr -> th_dport);
	printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
		struct libnet_ipv4_hdr *ipv4hdr = (struct libnet_ipv4_hdr *)(packet + 14);
		u_int8_t iplen;
		iplen = (ipv4hdr->ip_hl)*4;
		struct libnet_tcp_hdr *tcphdr = (struct libnet_tcp_hdr *)(packet + 14 + iplen);

		u_int8_t tcp_off = tcphdr->th_off;
		tcp_off = ((tcp_off & 0x0F) << 4) | ((tcp_off& 0xF0) >> 4);
		tcp_off = tcp_off *4;
		int tcp_data_offset = 14 + iplen + tcp_off;
		int tcp_data_size = header->caplen - tcp_data_offset;

		if(ipv4hdr -> ip_p != 6){
			printf("Is it TCP??\n");
			continue;
		}

		eth(eth_hdr);
		iph(ipv4hdr);
		tcph(tcphdr);

		printf("TCP Data : \n");
		if(tcp_data_size != 0){
			for (int i = 0; i < 10; ++i) {
				printf("%02x ", packet[tcp_data_offset + i]);
			}
		}

		printf("\n");
		printf("\n");

	}
	pcap_close(pcap);
	return 0;
}
