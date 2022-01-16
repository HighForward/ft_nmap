#include "../includes/ft_nmap.h"

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;

    if ( len == 1 )
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return (result);
}

void fill_icmp_packet(ICMP_pkt *ping_pkt)
{
    int i;

    (*ping_pkt).hdr.type = ICMP_ECHO;
    (*ping_pkt).hdr.code = 0;
    (*ping_pkt).hdr.un.echo.id = getpid();
    (*ping_pkt).hdr.un.echo.sequence++;

    for (i = 0; i < sizeof((*ping_pkt).msg) - 1; i++)
        (*ping_pkt).msg[i] = (char)(i + '0');
    (*ping_pkt).msg[i] = 0;

    (*ping_pkt).hdr.checksum = 0;
    (*ping_pkt).hdr.checksum = checksum(&(*ping_pkt), sizeof((*ping_pkt)));
}

int send_icmp_data(struct nmap *nmap, struct ICMP_pkt *icmp_pkt)
{

    if (sendto(nmap->icmp_socket, icmp_pkt, sizeof(ICMP_pkt), 0, (struct sockaddr *)&nmap->host_target, sizeof(struct sockaddr)) < 0)
        str_error("error sendto", 1);

    return (1);
}

int recv_icmp(struct nmap *nmap)
{
    unsigned char pck_reply[(sizeof(struct ip) + 4 + 150 + sizeof(struct ip) + sizeof(struct ICMP_pkt))];
    unsigned int size = sizeof(struct sockaddr_in);
    struct sockaddr_in from;

    if (recvfrom(nmap->icmp_socket, pck_reply, sizeof(pck_reply), 0, (struct sockaddr *) &from, &size) >= 0)
    {
        char ip[INET_ADDRSTRLEN];
        bzero(ip, sizeof(ip));

        inet_ntop(from.sin_family, &from.sin_addr, ip, INET_ADDRSTRLEN);
        ICMP_pkt *tmp_ICMP;
        tmp_ICMP = (ICMP_pkt *) (pck_reply + sizeof(struct ip));
        if (tmp_ICMP->hdr.code == 0 && tmp_ICMP->hdr.type == 0)
        {
//            printf("icmp reply\n");
        }
    } else
        printf("icmp not received\n");
}

int perform_icmp(nmap *nmap)
{
    nmap->icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nmap->icmp_socket < 0)
        str_error("permission denied, contact your administrator", 1);

    ICMP_pkt icmp_pkt;

    fill_icmp_packet(&icmp_pkt);

    send_icmp_data(nmap, &icmp_pkt);

    recv_icmp(nmap);
}