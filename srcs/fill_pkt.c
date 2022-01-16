#include "../includes/ft_nmap.h"

int fill_tcp_header(struct tcphdr *tcph, struct nmap *nmap)
{
    tcph->source = htons ( 43591 );
    tcph->dest = htons (80);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons ( 60000 );	// maximum allowed window size
    tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcph->urg_ptr = 0;
    tcph->check = 0;
}

int fill_ip_header(struct iphdr *iph, struct nmap *nmap)
{
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons (54321);
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;		//Set to 0 before calculating checksum
    iph->saddr = inet_addr( nmap->src_ip );	//Spoof the source ip address
    iph->daddr = inet_addr( nmap->dest_ip );
    iph->check = 0;
}

int fill_pseudo_header(struct pseudo_header *psh, struct nmap *nmap)
{
    psh->source_address = inet_addr(nmap->src_ip);
    psh->dest_address = inet_addr(nmap->dest_ip);
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(sizeof(struct tcphdr));
}