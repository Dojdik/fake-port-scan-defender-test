#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif // _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 65536

int stopped = 0;

int main(int argc, char * argv[]) {

    struct in_addr target_addr;
    target_addr.s_addr = inet_addr(argv[1]);
    system("iptables -t raw -I OUTPUT -p tcp --tcp-flags RST RST -j DROP"); //drop rst packets from kernel

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (!fd) {
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
                struct tcphdr *tcph = (struct tcphdr *) (buff + sizeof(iph));

                if (tcph->th_flags & (TH_SYN | TH_ACK)) {
                    printf("syn ack\n");
                }
            }
        } else if (rcvd == 0) {
            break;
        } else {
            perror("recvfrom");
            return 1;
        }
    }
}