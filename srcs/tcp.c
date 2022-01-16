#include "../includes/ft_nmap.h"

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

char *get_local_ip(char *host)
{
    struct ifaddrs *ifaddr;
    int family, s;

    if (getifaddrs(&ifaddr) == -1)
        str_error("getifaddrs", 1);

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET && strcmp(ifa->ifa_name, "eth0") == 0) {
            if (getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in), host, NI_MAXHOST,NULL, 0, NI_NUMERICHOST) != 0)
                str_error("error getnameinfo", 1);

            break;
        }
    }
}

int perform_tcp(struct nmap *nmap)
{
    get_local_ip(nmap->src_ip);

    int tcp_socket = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
    if (tcp_socket < 0)
        str_error("tcp socket failed", 1);

    int one = 1;
    const int *val = &one;

    if (setsockopt (tcp_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof (val)) < 0)
        str_error("cannot set IP_HDRINCL to socket", 1);

    //Datagram to represent the packet
    char datagram[4096];
    memset (datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh = {0};

    printf("local ip: %s : target ip: %s\n", nmap->src_ip, nmap->dest_ip);

    fill_ip_header(iph, nmap);
    fill_tcp_header(tcph, nmap);
//    fill_pseudo_header(&psh, nmap); ??????????????????


    //now change dest port on scanning loop (maybe other modif)
    tcph->dest = htons ( 100 );
    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

//    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr)); ????????????????

    if ( sendto (tcp_socket, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &nmap->host_target, sizeof (struct sockaddr_in)) < 0)
    {
        printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

}