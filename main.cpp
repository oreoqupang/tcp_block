#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN	6
#define TYPE_IPV4 0x0800
#define TYPE_TCP 0x6
#define ETHERNET_SIZE 14

struct sniff_ethernet {
		uint8_t ether_dhost[ETHER_ADDR_LEN];
		uint8_t ether_shost[ETHER_ADDR_LEN];
		uint16_t ether_type;
};

struct sniff_ip {
		uint8_t ip_vhl;
		uint8_t ip_tos;
		uint16_t ip_len;
		uint16_t ip_id;
		uint16_t ip_off;
		uint8_t ip_ttl;
		uint8_t ip_p;
		uint16_t ip_sum;
		struct in_addr ip_src,ip_dst;
};

struct sniff_tcp {
		uint16_t th_sport;
		uint16_t th_dport;
		uint32_t th_seq;
		uint32_t th_ack;
		uint8_t th_offset;
		uint8_t th_flags;
		uint16_t th_win;
		uint16_t th_sum;
		uint16_t th_urp;
};

struct pre_header {
	struct in_addr ip_src, ip_dst;
	uint8_t reserved;
	uint8_t protocol;
	uint16_t tcp_len;
};

char * target_host;

void usage() {
  printf("syntax: tcp_block <interface> <host>\n");
  printf("sample: tcp_block wlan0 test.gilgil.net\n");
}

uint16_t cal_ip_chk(uint16_t * ip_header, int ip_size){
	uint32_t res, add;

	res = 0;
	for(int i=0; i<ip_size/2; i++){
		if(i==5) continue;
		res+=ntohs(ip_header[i]);
	}

	if(res >> 16){
		add = res>>16;
		res = res&0xffff;
		res += add;

		if(res>>16){
			res += res>>16;
		}
	}
	return  htons((~res)&0xffff);
}

uint16_t cal_tcp_chk(struct sniff_ip * ip_header){
	struct pre_header pre;
	uint32_t ip_size, res, add, tcp_size;

	ip_size = (((ip_header)->ip_vhl) & 0x0f)*4;
	tcp_size = ntohs(ip_header->ip_len)-ip_size;

	pre.ip_src =  ip_header->ip_src;
	pre.ip_dst = ip_header->ip_dst;
	pre.reserved = 0;
	pre.protocol = ip_header->ip_p;
	pre.tcp_len = htons(tcp_size);

	uint16_t *p1, *p2;
	p1 = (uint16_t*)(&pre);
	p2 = (uint16_t*)(((uint8_t*)ip_header)+ip_size);

	res=0;
	for(int i=0; i<6; i++) res+=ntohs(p1[i]);
	for(int i=0; i<tcp_size/2; i++){
		if(i==8) continue;
		res+=ntohs(p2[i]);
	}

	if(res >> 16){
		add = res>>16;
		res = res&0xffff;
		res += add;

		if(res>>16){
			res += res>>16;
		}
	}
	return  htons((~res)&0xffff);
}


int f_fin(pcap_t* handle, const uint8_t * old_packet){
	uint32_t new_ack, new_syn, old_ack, old_syn, ip_size, data_size, tcp_size;
	uint8_t* packet;

	struct sniff_ip * old_ip = (struct sniff_ip *)(old_packet + ETHERNET_SIZE);
	ip_size = (((old_ip)->ip_vhl) & 0x0f)*4;
	struct sniff_tcp * old_tcp = (struct sniff_tcp *)(old_packet + ETHERNET_SIZE + ip_size);
	tcp_size = (((old_tcp)->th_offset & 0xf0) >> 4)*4;
	packet = (uint8_t*)malloc(ETHERNET_SIZE+ip_size+tcp_size);
	memcpy(packet, old_packet, ETHERNET_SIZE+ip_size+tcp_size);

	struct sniff_ip * ip = (struct sniff_ip *)(packet + ETHERNET_SIZE);
	struct sniff_tcp * tcp = (struct sniff_tcp *)(packet + ETHERNET_SIZE + ip_size);
	data_size = ntohs(ip->ip_len) - ip_size - (((tcp)->th_offset & 0xf0) >> 4)*4;

	old_syn = __builtin_bswap32(tcp->th_seq);
	old_ack = __builtin_bswap32(tcp->th_ack);
	new_syn = old_syn + data_size;
	new_ack = old_syn;

	tcp->th_flags = 0x1;
	tcp->th_seq =  __builtin_bswap32(new_syn);
	tcp->th_ack =  __builtin_bswap32(new_ack);
	ip->ip_len = htons(ip_size + tcp_size);

	ip->ip_sum = cal_ip_chk((uint16_t*)ip ,ip_size);
	tcp->th_sum = cal_tcp_chk(ip);

	if(pcap_sendpacket(handle, packet, ETHERNET_SIZE+ntohs(ip->ip_len))==-1)
  {
          printf("send errror\n");
					free(packet);
        	return -1;
	}
	free(packet);
	return 0;
}

int b_fin(pcap_t* handle, const uint8_t * old_packet){
	uint16_t t_port;
	uint32_t new_ack, new_syn, old_ack, old_syn, ip_size, data_size, tcp_size;
	struct in_addr tmp;
	char * contents = "HTTP/1.0 302 Redirect\x0d\x0aLocation: http://warning.or.kr/i1.html\x0d\x0a\x0d\x0a";
	uint8_t * packet;

	struct sniff_ip * old_ip = (struct sniff_ip *)(old_packet + ETHERNET_SIZE);
	ip_size = (((old_ip)->ip_vhl) & 0x0f)*4;
	struct sniff_tcp * old_tcp = (struct sniff_tcp *)(old_packet + ETHERNET_SIZE + ip_size);
	tcp_size = (((old_tcp)->th_offset & 0xf0) >> 4)*4;
	packet = (uint8_t*)malloc(ETHERNET_SIZE+ip_size+tcp_size+strlen(contents)+1);

	memcpy(packet, old_packet, ETHERNET_SIZE+ip_size+tcp_size);
	strcpy((char*)packet+ETHERNET_SIZE+ip_size+tcp_size, contents);

	struct sniff_ip * ip = (struct sniff_ip *)(packet + ETHERNET_SIZE);
	struct sniff_tcp * tcp = (struct sniff_tcp *)(packet + ETHERNET_SIZE + ip_size);
	data_size = ntohs(ip->ip_len) - ip_size - (((tcp)->th_offset & 0xf0) >> 4)*4;

	old_syn = __builtin_bswap32(tcp->th_seq);
	old_ack = __builtin_bswap32(tcp->th_ack);
	new_syn = old_ack;
	new_ack = old_syn+data_size;

	tcp->th_flags = 0x1;
	tcp->th_seq =  __builtin_bswap32(new_syn);
	tcp->th_ack =  __builtin_bswap32(new_ack);

	t_port = tcp->th_dport;
	tcp->th_dport = tcp->th_sport;
	tcp->th_sport = t_port;

	tmp = ip->ip_src;
	ip->ip_src = ip->ip_dst;
	ip->ip_dst = tmp;
	ip->ip_len = htons(ip_size+tcp_size+strlen(contents)+1);

	struct sniff_ethernet * ether = (struct sniff_ethernet *)packet;
	uint8_t tmp_addr[ETHER_ADDR_LEN];
	memcpy(tmp_addr, ether->ether_dhost, ETHER_ADDR_LEN);
	memcpy(ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN);
	memcpy(ether->ether_shost, tmp_addr, ETHER_ADDR_LEN);

	ip->ip_sum = cal_ip_chk((uint16_t*)ip ,ip_size);
	tcp->th_sum = cal_tcp_chk(ip);

	if(pcap_sendpacket(handle, packet, ETHERNET_SIZE+ntohs(ip->ip_len))==-1)
  {
          printf("send errror\n");
					free(packet);
        	return -1;
	}
	free(packet);
	return 0;
}

int f_rst(pcap_t* handle, const uint8_t * old_packet){
	uint32_t new_ack, new_syn, old_ack, old_syn, ip_size, data_size, tcp_size;
	uint8_t* packet;

	struct sniff_ip * old_ip = (struct sniff_ip *)(old_packet + ETHERNET_SIZE);
	ip_size = (((old_ip)->ip_vhl) & 0x0f)*4;
	struct sniff_tcp * old_tcp = (struct sniff_tcp *)(old_packet + ETHERNET_SIZE + ip_size);
	tcp_size = (((old_tcp)->th_offset & 0xf0) >> 4)*4;
	packet = (uint8_t*)malloc(ETHERNET_SIZE+ip_size+tcp_size);
	memcpy(packet, old_packet, ETHERNET_SIZE+ip_size+tcp_size);

	struct sniff_ip * ip = (struct sniff_ip *)(packet + ETHERNET_SIZE);
	struct sniff_tcp * tcp = (struct sniff_tcp *)(packet + ETHERNET_SIZE + ip_size);
	data_size = ntohs(ip->ip_len) - ip_size - (((tcp)->th_offset & 0xf0) >> 4)*4;

	old_syn = __builtin_bswap32(tcp->th_seq);
	old_ack = __builtin_bswap32(tcp->th_ack);
	new_syn = old_syn + data_size;
	new_ack = old_syn;

	tcp->th_flags = 0x1<<2;
	tcp->th_seq =  __builtin_bswap32(new_syn);
	tcp->th_ack =  __builtin_bswap32(new_ack);
	ip->ip_len = htons(ip_size + tcp_size);

	ip->ip_sum = cal_ip_chk((uint16_t*)ip ,ip_size);
	tcp->th_sum = cal_tcp_chk(ip);

	if(pcap_sendpacket(handle, packet, ETHERNET_SIZE+ntohs(ip->ip_len))==-1)
  {
          printf("send errror\n");
					free(packet);
        	return -1;
	}
	free(packet);
	return 0;

}

int b_rst(pcap_t* handle, const uint8_t * old_packet){
	uint16_t t_port;
	uint32_t new_ack, new_syn, old_ack, old_syn, ip_size, data_size, tcp_size;
	uint8_t * packet;
	struct in_addr tmp;

	struct sniff_ip * old_ip = (struct sniff_ip *)(old_packet + ETHERNET_SIZE);
	ip_size = (((old_ip)->ip_vhl) & 0x0f)*4;
	struct sniff_tcp * old_tcp = (struct sniff_tcp *)(old_packet + ETHERNET_SIZE + ip_size);
	tcp_size = (((old_tcp)->th_offset & 0xf0) >> 4)*4;
	packet = (uint8_t*)malloc(ETHERNET_SIZE+ip_size+tcp_size);
	memcpy(packet, old_packet, ETHERNET_SIZE+ip_size+tcp_size);

	struct sniff_ip * ip = (struct sniff_ip *)(packet + ETHERNET_SIZE);
	struct sniff_tcp * tcp = (struct sniff_tcp *)(packet + ETHERNET_SIZE + ip_size);
	data_size = ntohs(ip->ip_len) - ip_size - (((tcp)->th_offset & 0xf0) >> 4)*4;

	old_syn = __builtin_bswap32(tcp->th_seq);
	old_ack = __builtin_bswap32(tcp->th_ack);
	new_syn = old_ack;
	new_ack = old_syn+data_size;

	tcp->th_flags = (0x1<<2);
	tcp->th_seq =  __builtin_bswap32(new_syn);
	tcp->th_ack =  __builtin_bswap32(new_ack);

	t_port = tcp->th_dport;
	tcp->th_dport = tcp->th_sport;
	tcp->th_sport = t_port;

	tmp = ip->ip_src;
	ip->ip_src = ip->ip_dst;
	ip->ip_dst = tmp;
	ip->ip_len = htons(ip_size+tcp_size);

	struct sniff_ethernet * ether = (struct sniff_ethernet *)packet;
	uint8_t tmp_addr[ETHER_ADDR_LEN];
	memcpy(tmp_addr, ether->ether_dhost, ETHER_ADDR_LEN);
	memcpy(ether->ether_dhost, ether->ether_shost, ETHER_ADDR_LEN);
	memcpy(ether->ether_shost, tmp_addr, ETHER_ADDR_LEN);

	ip->ip_sum = cal_ip_chk((uint16_t*)ip ,ip_size);
	tcp->th_sum = cal_tcp_chk(ip);

	if(pcap_sendpacket(handle, packet, ETHERNET_SIZE+ntohs(ip->ip_len))==-1)
  {
          printf("send errror\n");
					free(packet);
        	return -1;
	}
	free(packet);
	return 0;
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    usage();
    return -1;
  }

  char* dev = argv[1];
	target_host = argv[2];
  char errbuf[PCAP_ERRBUF_SIZE];
	char victim[100];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t* packet, * data;
		uint32_t ip_size, tcp_size, data_size, port;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

		struct sniff_ethernet * ethernet = (struct sniff_ethernet *)packet;
		if(ntohs(ethernet->ether_type) != TYPE_IPV4) continue;

		struct sniff_ip * ip = (struct sniff_ip *)(packet + ETHERNET_SIZE);
		if(ip->ip_p != TYPE_TCP) continue;
		ip_size = (((ip)->ip_vhl) & 0x0f)*4;

		struct sniff_tcp * tcp = (struct sniff_tcp *)(packet + ETHERNET_SIZE + ip_size);
		tcp_size = (((tcp)->th_offset & 0xf0) >> 4)*4;
		port = ntohs(tcp->th_dport);

		if(port == 80 || port == 443){
			data = (packet+ETHERNET_SIZE+ip_size+tcp_size);
			if( !memcmp(data, "GET", 3) || !memcmp(data, "POST", 4) || !memcmp(data, "HEAD", 4) || !memcmp(data, "PUT", 3) || !memcmp(data, "DELETE", 6) || !memcmp(data, "OPTIONS", 7)){
				snprintf(victim, 100, "Host: %s", target_host);
				if(strstr((char*)data, victim)) {
					printf("BLOCK!!\n");
					f_fin(handle, packet);
					b_fin(handle, packet);
					/*f_rst(handle, packet);
						b_rst(handle, packet);
					*/
				}
			}
		}

	}

  pcap_close(handle);
  return 0;
}
