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

// Protocol values
// Internet Layer
#define IP 2048
#define ARP 2054
// Transport Layer
#define ICMP 1
#define TCP 6
#define UDP 17

#define ETH_HEADER_LENGTH 14

int extractEthernetHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header);

int extractIPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header);
void extractARPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header);

void extractICMPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header, int cursor);
void extractUDPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header, int cursor);
void extractTCPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header, int cursor);

char* getTransportProtocol(unsigned char value);
int isValidIPChecksum(const unsigned char* pkt_data, int header_length, int cursor);
int isValidTCPChecksum(const unsigned char* pkt_data, int header_length, int cursor);

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

        printf("\nPacket number: %d  Frame Len: %d\n\n", pkt_number, pkt_header->len);

        int internet_type = extractEthernetHeader(pkt_data, pkt_header);
        int data_offset;
        // if IP Header
        if(internet_type == IP) {
            data_offset = extractIPHeader(pkt_data, pkt_header);
            // check protocol type
            // if ICMP
            if(pkt_data[23] == ICMP) {
                extractICMPHeader(pkt_data, pkt_header, data_offset + ETH_HEADER_LENGTH);
            }
            else if(pkt_data[23] == UDP) {
                extractUDPHeader(pkt_data, pkt_header, data_offset + ETH_HEADER_LENGTH);
            }
            else if(pkt_data[23] == TCP) {
                extractTCPHeader(pkt_data, pkt_header, data_offset + ETH_HEADER_LENGTH);
            }
        }
        // if ARP Header
        if(internet_type == ARP) {
            extractARPHeader(pkt_data, pkt_header);
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
int extractEthernetHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header) {
    
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n",ether_ntoa((struct ether_addr *)&pkt_data[0]));
    printf("\t\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)&pkt_data[6]));
    
    unsigned short type_value;
    memcpy(&type_value, &pkt_data[12], 2);
    type_value = ntohs(type_value);
    char* type;
    if(type_value == IP) {
        type = "IP";
        printf("\t\tType: %s\n\n", type);
    }
    else if(type_value == ARP) {
        type = "ARP";
        printf("\t\tType: %s\n\n", type);
    }
    else
        printf("\t\tType: Not Supported\n\n");

    return type_value;
}

int extractIPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header) {

    // IP Header starting point
    int cursor = ETH_HEADER_LENGTH;

    int header_length = (pkt_data[cursor] & 0x0F) * 4;
    unsigned char protocol_value = pkt_data[cursor + 9];
    char* protocol = getTransportProtocol(protocol_value);

    printf("\tIP Header\n");
    printf("\t\tHeader Len: %d (bytes)\n", header_length);
    printf("\t\tTOS: 0x%x\n", pkt_data[cursor + 1]);
    printf("\t\tTTL: %d\n", pkt_data[cursor + 8]);

    short pdu_length;
    memcpy(&pdu_length, &pkt_data[cursor + 2], 2);
    pdu_length = ntohs(pdu_length);
    printf("\t\tIP PDU Len: %d (bytes)\n", pdu_length);

    printf("\t\tProtocol: %s\n", protocol);

    // validate checksum
    if(isValidIPChecksum(pkt_data, header_length, cursor) == 0) {
        unsigned short checksum;
        memcpy(&checksum, &pkt_data[cursor + 10], 2);
        printf("\t\tChecksum: Correct (0x%x)\n", checksum);
    }
    else {
        unsigned short checksum;
        memcpy(&checksum, &pkt_data[cursor + 10], 2);
        printf("\t\tChecksum: Incorrect (0x%x)\n", checksum);
    }

    // get sender and destination IPs
    struct in_addr address_buff;
    memcpy(&address_buff, &pkt_data[cursor + 12], sizeof(struct in_addr));
    printf("\t\tSender IP: %s\n", inet_ntoa(address_buff));
    memcpy(&address_buff, &pkt_data[cursor + 16], sizeof(struct in_addr));
    printf("\t\tDest IP: %s\n\n", inet_ntoa(address_buff));

    return header_length;
}

void extractARPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header) {

    // ARP Header starting point
    int cursor = ETH_HEADER_LENGTH;

    printf("\tARP header\n");
    // get opcode
    if(pkt_data[cursor + 7] == 1)
        printf("\t\tOpcode: Request\n");
    else if (pkt_data[cursor + 7] == 2)
        printf("\t\tOpcode: Reply\n");
    else
        printf("\t\tOpcode: Not a valid opcode: %d\n", pkt_data[cursor + 7]);

    // get sender and target MACs and IPs
    printf("\t\tSender MAC: %s\n", ether_ntoa((struct ether_addr *)&pkt_data[cursor + 8]));

    struct in_addr address_buff;
    memcpy(&address_buff, &pkt_data[cursor + 14], sizeof(struct in_addr));
    printf("\t\tSender IP: %s\n", inet_ntoa(address_buff));

    printf("\t\tTarget MAC: %s\n",ether_ntoa((struct ether_addr *)&pkt_data[cursor + 18]));

    memcpy(&address_buff, &pkt_data[cursor + 24], sizeof(struct in_addr));
    printf("\t\tTarget IP: %s\n\n", inet_ntoa(address_buff));
    
}

void extractICMPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header, int cursor) {
    printf("\tICMP Header\n");
    if(pkt_data[cursor] == 8)
        printf("\t\tType: Request\n\n");
    else if(pkt_data[cursor] == 0)
        printf("\t\tType: Reply\n\n");
    else
        printf("\t\tType: Invalid Type\n");
}

void extractUDPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header, int cursor) {
    printf("\tUDP Header\n");
    // get port numbers
    unsigned short port;
    memcpy(&port, &pkt_data[cursor], 2);
    port = ntohs(port);
    printf("\t\tSource Port: : %d\n", port);
    memcpy(&port, &pkt_data[cursor + 2], 2);
    port = ntohs(port);
    printf("\t\tDest Port: : %d\n", port);
}

void extractTCPHeader(const unsigned char* pkt_data, struct pcap_pkthdr* pkt_header, int cursor) {
    printf("\tTCP Header\n");
    // get port numbers
    unsigned short port;
    memcpy(&port, &pkt_data[cursor], 2);
    port = ntohs(port);
    printf("\t\tSource Port: : %d\n", port);
    memcpy(&port, &pkt_data[cursor + 2], 2);
    port = ntohs(port);
    printf("\t\tDest Port: : %d\n", port);

    // get sequence number
    unsigned long seq_num;
    memcpy(&seq_num, &pkt_data[cursor + 4], 4);
    seq_num = ntohl(seq_num);
    printf("\t\tSequence Number: %lu\n", seq_num);

    // check flags
    unsigned char flags = pkt_data[cursor + 13];
    // check ACK flag and print ACK number accordingly
    if((flags & 0x10) == 0x10) {
        unsigned long ack_num;
        memcpy(&ack_num, &pkt_data[cursor + 8], 4);
        ack_num = ntohl(ack_num);
        printf("\t\tACK Number: %lu\n", ack_num);
        printf("\t\tACK Flag: Yes\n");
    }
    else {
        printf("\t\tACK Number: <not valid>\n");
        printf("\t\tACK Flag: No\n");
    }

    // check rest of flags
    if((flags & 0x2) == 0x2) {
        printf("\t\tSYN Flag: Yes\n");
    }
    else printf("\t\tSYN Flag: No\n");
    if((flags & 0x4) == 0x4) {
        printf("\t\tRST Flag: Yes\n");
    }
    else printf("\t\tRST Flag: No\n");
    if((flags & 0x1) == 0x1) {
        printf("\t\tFIN Flag: Yes\n");
    }
    else printf("\t\tFIN Flag: No\n");
    
    // window size
    unsigned short window_size;
    memcpy(&window_size, &pkt_data[cursor + 14], 2);
    window_size = ntohs(window_size);
    printf("\t\tWindow Size: %hu\n", window_size);
    
    // TCP pseudoheader checksum
    int res = isValidTCPChecksum(pkt_data, pkt_header->len, cursor);
    if(res == 0) {
        unsigned short checksum;
        memcpy(&checksum, &pkt_data[cursor + 16], 2);
        printf("\t\tChecksum: Correct (0x%x)\n", checksum);
    }
    else {
        unsigned short checksum;
        memcpy(&checksum, &pkt_data[cursor + 16], 2);
        printf("\t\tChecksum: Incorrect (0x%x)\n", checksum);
    }

}

char* getTransportProtocol(unsigned char value) {
    if(value == ICMP)
        return "ICMP";
    else if(value == TCP)
        return "TCP";
    else if(value == UDP)
        return "UDP";
    else
        return "protocol not defined in this program";
}

// Checks if IP header checksum is valid. returns 0 on true, anything else on false.
int isValidIPChecksum(const unsigned char* pkt_data, int header_length, int cursor) {
    // copy header data
    unsigned char* checksum_buff = malloc(sizeof(unsigned char) * header_length);
    memcpy(checksum_buff, &pkt_data[cursor], header_length);
    
    int result = in_cksum((unsigned short*) checksum_buff, header_length);

    free(checksum_buff);
    return result;
}

// Checks if TCP header checksum is valid. returns 0 on true, anything else on false.
int isValidTCPChecksum(const unsigned char* pkt_data, int packet_length, int cursor) {

    // find length needed for checksum buffer
    int length;
    // pseudo-header
    length = 12;
    // tcp header length
    //length += (pkt_data[cursor + 12] & 0x0F) * 4;
    // tcp data
    // packet size
    length += (packet_length);
    // - IP header size
    int ip_header_length = (pkt_data[ETH_HEADER_LENGTH] & 0x0F) * 4;
    length -= (ip_header_length + ETH_HEADER_LENGTH);
    unsigned char* checksum_buff = malloc(sizeof(unsigned char) * length);

    // get src and dest addresses
    memcpy(&checksum_buff[0], &pkt_data[26], 8);
    // reserved
    memset(&checksum_buff[8], 0, 1);
    // protocol
    memcpy(&checksum_buff[9], &pkt_data[23], 1);
    unsigned short tcp_payload_length = packet_length - ((pkt_data[cursor + 12] & 0xF0) / 16) * 4 - ip_header_length - ETH_HEADER_LENGTH;
    // tcp payload length
    memcpy(&checksum_buff[10], &tcp_payload_length, 2);
    // tcp header + data
    memcpy(&checksum_buff[12], &pkt_data[cursor], tcp_payload_length + ((pkt_data[cursor + 12] & 0xF0) / 16) * 4);
    //memset(&checksum_buff[12 + cursor + 16], 0, 2);

    int result = in_cksum((unsigned short*) checksum_buff, length);

    printf("size: ");
    int what = 0;
    for(int i = 0; i < length; i++) {
        printf("%x ", checksum_buff[i]);
        what++;
    }
    printf("\n%d\n", what);

    printf("\n(0x%x)\n", result);


    free(checksum_buff);
    return result;
}