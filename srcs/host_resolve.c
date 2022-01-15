#include "../includes/ft_nmap.h"

int host_resolve(struct nmap *nmap)
{
    struct hostent* host = gethostbyname(nmap->arg_host);
    if (!host)
        str_error("host do not exists on the internet",1);

    nmap->hostent = host;

    bzero(&nmap->host_target, sizeof(nmap->host_target));

    memcpy(&nmap->host_target.sin_addr, nmap->hostent->h_addr_list[0], nmap->hostent->h_length);
    nmap->host_target.sin_family = AF_INET;

    return (1);
}