#ifndef FT_NMAP
#define FT_NMAP

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socketvar.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <signal.h>

#include <pcap.h>
#include <ifaddrs.h>

#include <errno.h>
#include <pthread.h>

#include<netinet/ip.h>	//Provides declarations for ip header
#include<net/ethernet.h>

#define PING_PACKET_SIZE 56

typedef struct ICMP_pkt
{
    struct icmphdr hdr;
    char msg[PING_PACKET_SIZE - sizeof(struct icmphdr)];

} ICMP_pkt;

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

typedef struct nmap
{
    int icmp_socket;
    char *arg_host;
    struct hostent *hostent;
    struct sockaddr_in host_target;
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
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
unsigned short csum(unsigned short *ptr,int nbytes);

//FILL_PKT
int fill_ip_header(struct iphdr *iph, struct nmap *nmap);
int fill_tcp_header(struct tcphdr *tcph, struct nmap *nmap);
int fill_pseudo_header(struct pseudo_header *psh, struct nmap *nmap);

//SNIFFER
int sniffer();
void *thread_sniffer(void *arg);

//THREAD
int launch_thread();

#endif