#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "checksum.h"

// wrong file extension
#define FILEEX -1
// cannot find file or directory
#define FILEDNE -2
// cannot open file
#define FILEOP -3
// incorrect arglist length
#define ARGL -4

// internet protocol values
// Internet Layer
#define IP 2048
#define ARP 2054
// Transport Layer
#define ICMP 1
#define TCP 6
#define UDP 17

int extractEthernetHeader(const unsigned char* pkt_data, int pkt_number, struct pcap_pkthdr* pkt_header);
int extractIPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header);

char* getProtocolValue(unsigned char value);

int main(int argc, char *argv[]) {

    // command line arguments error checking
    if(argc < 2) {
        fprintf(stderr, "Usage: trace [.pcap file]\n");
        return ARGL;
    }
    const char *period = strrchr(argv[1], '.');
    if(!period || period == argv[1]) {
        fprintf(stderr, "Wrong file type. Must use a .pcap file.\n");
        return FILEEX;
    }
    if(strcmp(period, ".pcap")) {
        fprintf(stderr, "Wrong file type. Must use a .pcap file.\n");
        return FILEEX;
    }

    /*

    int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);

    */

    struct pcap_pkthdr* pkt_header;
    const unsigned char* pkt_data;

    char* err_buff = malloc(1000 * sizeof(char));

    // open .pcap file
    pcap_t* save_file = pcap_open_offline(argv[1], err_buff);
    if(save_file == NULL) {
        fprintf(stderr, ".pcap open file error. Error text: %s\n", err_buff);
        free(err_buff);
        return FILEOP;
    }

    int res;
    int pkt_number = 1;

    // read every pcap file
    while((res = pcap_next_ex(save_file, &pkt_header, &pkt_data)) == 1) {
        int type = extractEthernetHeader(pkt_data, pkt_number, pkt_header);
        int offset;
        // if IP Header
        if(type == IP) {
            offset = extractIPHeader(pkt_data, pkt_header);
        }
        // if ARP Header
        if(type == ARP) {

        }
        pkt_number++;

    }
    if(res != -2) {
        fprintf(stderr, ".pcap savefile read failure. pcap_next_ex return value: %d\n", res);
    }

      
    pcap_close(save_file);
    free(err_buff);
    return 0;
}

// extract ethernet header and frame information. returns protocol type (e.g. IP, ARP).
int extractEthernetHeader(const unsigned char* pkt_data, int pkt_number, struct pcap_pkthdr* pkt_header) {

    printf("Packet number: %d  Frame Len: %d\n\n", pkt_number, pkt_header->len);
    
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: ");
    for (int i = 0; i < 6; i++) {
        if(i < 5)
            printf("%x:", pkt_data[i]);
        else printf("%x", pkt_data[i]);
    }
    printf("\n\t\tSource MAC: ");
    for (int i = 6; i < 12; i++) {
        if(i < 11)
            printf("%x:", pkt_data[i]);
        else printf("%x", pkt_data[i]);
    }
    unsigned short type_value;
    memcpy(&type_value, &pkt_data[12], 2);
    type_value = ntohs(type_value);
    char* type;
    if(type_value == IP) {
        type = "IP";
    }
    else if(type_value == ARP) {
        type = "ARP";
    }
        
    printf("\n\t\tType: %s\n\n", type);

    return type_value;
}

int extractIPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header) {

    // IP Header starting point
    int cursor = 14;

    int header_length = pkt_data[cursor] & 0x0F * 4;
    unsigned char protocol_value = pkt_data[cursor + 9];
    char* protocol = getProtocolValue(protocol_value);

    printf("\tIP Header\n");
    printf("\t\tHeader Len: %d (bytes)\n", header_length);
    printf("\t\tTOS: 0x%x\n", pkt_data[cursor + 1]);
    printf("\t\tTTL: %d\n", pkt_data[cursor + 8]);
    printf("\t\tIP PDU Len: %d (bytes)\n", pkt_data[cursor + 3]);
    printf("\t\tProtocol: %s\n", protocol);
    

    return header_length;
}

char* getProtocolValue(unsigned char value) {
    if(value == ICMP)
        return "ICMP";
    else if(value == TCP)
        return "TCP";
    else if(value == UDP)
        return "UDP";
    else
        return "protocol not defined in this program";

}