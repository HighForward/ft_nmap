#include "../includes/ft_nmap.h"

int launch_thread()
{
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, thread_sniffer, NULL);
//    pthread_join(thread_id, NULL);
}