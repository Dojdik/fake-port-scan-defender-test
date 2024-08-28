#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif // _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/signal.h>

#define BUF_SIZE 65536
#define OPT_SIZE 20

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes)
{
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}


int stopped = 0;

void sigint_handler(int signal) {
    stopped = 1;
}

int main(int argc, char * argv[]) {

    signal(SIGINT, sigint_handler);

    if (argc < 2) {
        printf("Usage: %s [target_addr]\n", argv[0]);
        return 1;
    }

    struct in_addr target_addr;
    target_addr.s_addr = inet_addr(argv[1]);

    if (target_addr.s_addr == -1) {
        printf("Invalid target addr\n");
        return 1;
    }

    fprintf(stderr, "Target addr: %s\n", inet_ntoa(target_addr));

    system("iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP"); //drop rst packets from kernel

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (fd <= 0) {
        perror("socket");
        return 1;
    }

    char buff[BUF_SIZE];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    while (!stopped) {
        int rcvd = recvfrom(fd, buff, BUF_SIZE, 0, (struct sockaddr *) &addr, &addr_len);

        if (rcvd > 0) {
            struct iphdr *iph = (struct iphdr *) buff;
            if (iph->daddr == target_addr.s_addr) {
                struct tcphdr *tcph = (struct tcphdr *) (buff + sizeof(struct iphdr));

                if (tcph->th_flags == TH_SYN) {

                    char datagram[40];

                    char options[] = {
                        0x02, 0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a,
                        0x13, 0x36, 0x7d, 0x28, 0x00, 0x00, 0x00, 0x00,
                        0x01, 0x03, 0x03, 0x07
                    };

                    tcph->doff = 10;

                    uint32_t tmp_seq = tcph->th_seq;
                    tcph->th_seq = rand();
                    tcph->th_ack = htonl(htonl(tmp_seq) + 1);

                    uint16_t tmp_port = tcph->th_sport;
                    tcph->th_sport = tcph->th_dport;
                    tcph->th_dport = tmp_port;

                    tcph->th_flags = TH_SYN | TH_ACK;
                    tcph->th_sum = 0;

                    struct pseudo_header psh;

                    psh.source_address = iph->daddr;
                    psh.dest_address = iph->saddr;
                    psh.placeholder = 0;
                    psh.protocol = IPPROTO_TCP;
                    psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);

                    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
                    char pseudogram[psize];
                    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
                    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
                    memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), options, OPT_SIZE);
                    tcph->th_sum = csum((unsigned short *)pseudogram, psize);


                    memcpy(datagram, tcph, sizeof(struct tcphdr));
                    memcpy(datagram + sizeof(struct tcphdr), options, OPT_SIZE);

                    int s = sendto(fd, datagram, 40, 0, (struct sockaddr *) &addr, addr_len);
                    
                    if (s <= 0) {
                        perror("sendto");
                    }
                }
            }
        } else if (rcvd == 0) {
            break;
        } else {
            perror("recvfrom");
            return 1;
        }
    }
    fprintf(stderr, "Stopped\n");
    system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP"); //drop rst packets from kernel
}