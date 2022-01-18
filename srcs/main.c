#include "../includes/ft_nmap.h"

int main(int argc, char **argv)
{
    struct nmap nmap;
    bzero(&nmap, sizeof(struct nmap));

    if (!perform_args(argv + 1, &nmap))
        str_error("error args", 1);

    if (!host_resolve(&nmap))
        str_error("error host resolve", 1);

    printf("Starting Nmap 1.00 ( mbrignol )\n");
    printf("ft_nmap scan report for %s (%s)\n", nmap.arg_host, nmap.arg_host);


    launch_thread();

    perform_icmp(&nmap);

    perform_tcp(&nmap);


    sleep(10);

    return 0;
}