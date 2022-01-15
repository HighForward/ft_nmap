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

int get_local_ip ( char * buffer)
{
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );

    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);

    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    close(sock);
}

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

int perform_tcp(struct nmap *nmap)
{
    int tcp_socket = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
    if (tcp_socket < 0)
        str_error("tcp socket failed", 1);

    struct sockaddr_in localaddr ;
    localaddr.sin_family = AF_INET; /* Protocole internet */
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localaddr.sin_port = htons(81);

    struct sockaddr_in remote = {0};
    remote.sin_addr.s_addr = inet_addr("179.60.192.3"); //Local Host
    remote.sin_family = AF_INET;
    remote.sin_port = htons(80);

    //Datagram to represent the packet
    char datagram[4096];
    memset (datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in  dest;
    struct pseudo_header psh = {0};

    struct in_addr dest_ip;
    dest_ip.s_addr = inet_addr("179.60.192.3");

    int source_port = 43591;
    char source_ip[20];
    get_local_ip(source_ip);
    printf("Local source IP is %s \n" , source_ip);
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
    iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
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
    tcph->window = htons ( 80 );	// maximum allowed window size
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

    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip.s_addr;


    psh.source_address = inet_addr( source_ip );
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons( sizeof(struct tcphdr) );

    memcpy(&psh.tcp , (void*)&tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));


    struct iphdr test;
    memcpy(&test, &datagram, sizeof(struct iphdr));




    if (sendto (tcp_socket, datagram,sizeof(struct iphdr) + sizeof(struct tcphdr),0 , (struct sockaddr *)&nmap->host_target, sizeof (struct sockaddr)) < 0)
    {
        printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
    }

}