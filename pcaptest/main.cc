#include "stdio.h"
#include "stdlib.h"
#include <pcap.h>
#include <iostream>
#include "string.h"

using namespace std;

#define MAX_BUFF   1024

class AAA
{
public:
	AAA() {};
	~AAA() {};

	int ss;
};
//链路层数据包格式
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
}ETHHEADER;
//IP层数据包格式
typedef struct {
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}IPHEADER;
//协议映射表
char *Proto[]={
    "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};

void packet_handler(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
	pcap_dumper_t* dumper = (pcap_dumper_t*) user;
	pcap_dump(user, header, pkt_data);

	ETHHEADER *eth_header = (ETHHEADER*) pkt_data;
	printf("---------------Begin Analysis-----------------\n");
	printf("----------------------------------------------\n");
	printf("Packet length: %d \n", header->len);
	//解析数据包IP头部
	if (header->len >= 14) {
		IPHEADER *ip_header = (IPHEADER*) (pkt_data + 14);
		//解析协议类型
		char strType[100];
		if (ip_header->proto > 7)
			strcpy(strType, "IP/UNKNWN");
		else
			strcpy(strType, Proto[ip_header->proto]);

		printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>",
				eth_header->SrcMac[0], eth_header->SrcMac[1],
				eth_header->SrcMac[2], eth_header->SrcMac[3],
				eth_header->SrcMac[4], eth_header->SrcMac[5]);
		printf("Dest   MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",
				eth_header->DestMac[0], eth_header->DestMac[1],
				eth_header->DestMac[2], eth_header->DestMac[3],
				eth_header->DestMac[4], eth_header->DestMac[5]);

		printf("Source IP : %d.%d.%d.%d==>", ip_header->sourceIP[0],
				ip_header->sourceIP[1], ip_header->sourceIP[2],
				ip_header->sourceIP[3]);
		printf("Dest   IP : %d.%d.%d.%d\n", ip_header->destIP[0],
				ip_header->destIP[1], ip_header->destIP[2],
				ip_header->destIP[3]);

		printf("Protocol : %s\n", strType);

		//显示数据帧内容
		int i;
		for (i = 0; i < (int) header->len; ++i) {
			printf(" %02x", pkt_data[i]);
			if ((i + 1) % 16 == 0)
				printf("\n");
		}
		printf("\n\n");
	}
	return;
}

int main(int argc, char** argv)
{
    cout << "start ...." << endl;
    char buff[MAX_BUFF] = {0};
    pcap_t* pcap = pcap_open_offline("./arp.cap", buff);
    if (pcap == NULL) 
    {
        cout << "Open pcap error!" << endl;
        return 0;
    }
    struct bpf_program filter;
    if (pcap_compile(pcap, &filter, "tcp or udp", 1, 0) < 0)
    {
        cout << "init filter error!" << endl;
    }
    if (pcap_setfilter(pcap, &filter) < 0)
    {
        cout << "set filter error!" << endl;
    }

    AAA* a = new AAA();
    a->ss = 1024;

    pcap_dumper_t* dumper = pcap_dump_open(pcap, "./arp_dump.pcap");
    if(dumper==NULL)
    {
    	cout << "Error opening output file\n" << endl;
        return -1;
    }

     pcap_loop(pcap, 0, packet_handler, (u_char*)dumper);
    
    pcap_close(pcap);
    pcap_dump_close(dumper);

    cout << "end" << endl;
    return 0;
}

