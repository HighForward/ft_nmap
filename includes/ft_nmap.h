#ifndef FT_NMAP
#define FT_NMAP

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netdb.h>

#include <sys/types.h>
#include <ifaddrs.h>

#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define PING_PACKET_SIZE 56

typedef struct ICMP_pkt
{
    struct icmphdr hdr;
    char msg[PING_PACKET_SIZE - sizeof(struct icmphdr)];

} ICMP_pkt;

typedef struct nmap
{
    int icmp_socket;
    char *arg_host;
    struct hostent *hostent;
    struct sockaddr_in host_target;
} nmap;

int str_error(char *str, int err);

//ICMP HANDLER
int perform_icmp(struct nmap *nmap);

//ARGS
int perform_args(char **argv, nmap *nmap);

//HOST RESOLVE
int host_resolve(struct nmap *nmap);


//TCP HANDLER
int perform_tcp(struct nmap *nmap);

#endif