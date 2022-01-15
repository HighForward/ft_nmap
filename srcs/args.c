#include "../includes/ft_nmap.h"

int perform_args(char **argv, nmap *nmap)
{
    if (argv[0])
        nmap->arg_host = argv[0];
    else
         return (0);
    return (1);
}