#include "../includes/ft_nmap.h"

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int get_local_ip()
{
    struct ifaddrs *ifaddr;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1)
    {
        printf("getifaddrs error\n");
        exit(EXIT_FAILURE);
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        /* Display interface name and family (including symbolic
           form of the latter for the common families). */

//        printf("%-8s %s (%d)\n",
//               ifa->ifa_name,
//               (family == AF_PACKET) ? "AF_PACKET" :
//               (family == AF_INET) ? "AF_INET" :
//               (family == AF_INET6) ? "AF_INET6" : "???",
//               family);

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) :
                            sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }

            printf("\t\taddress: <%s>\n", host);

        }
    }
}

int perform_tcp(struct nmap *nmap)
{

    int tcp_socket = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
    if (tcp_socket < 0)
        str_error("tcp socket failed", 1);

    //Datagram to represent the packet
    char datagram[4096];
    memset (datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));

    struct pseudo_header psh = {0};

    char *target = "179.60.192.3";
    char *source = "172.19.0.2";

    struct in_addr dest_ip;
    dest_ip.s_addr = inet_addr(target);

    int source_port = 43591;
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons (54321);	//Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;		//Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source );	//Spoof the source ip address
    iph->daddr = dest_ip.s_addr;
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    //TCP Header
    tcph->source = htons ( source_port );
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

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt (tcp_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof (val)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

    struct sockaddr_in  dest;

    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip.s_addr;

    tcph->dest = htons ( 80 );
    tcph->check = 0;
//
    psh.source_address = inet_addr( source );
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons( sizeof(struct tcphdr) );

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
    if ( sendto (tcp_socket, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
    {
        printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

}