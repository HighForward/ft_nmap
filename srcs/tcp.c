#include "../includes/ft_nmap.h"

int perform_tcp(struct nmap *nmap)
{

    int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
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

//    if (bind(tcp_socket, (struct sockaddr*)&localaddr, sizeof(localaddr)) == -1) {
//        // Traitement de l'erreur;
//    }
//    else
//    {
//        printf("succes bind\n");
//    }

    int ret = connect(tcp_socket, (struct sockaddr*)&remote, sizeof(struct sockaddr_in));
    if (ret == 0)
        printf("connect success");
//
//    remote.sin_addr.s_addr = inet_addr("179.60.192.3"); //Local Host
//    remote.sin_family = AF_INET;
//    remote.sin_port = htons(443);
//
//    ret = connect(tcp_socket, (struct sockaddr*)&remote, sizeof(struct sockaddr_in));
//    if (ret == 0)
//        printf("connect success");
    printf("%s\n", strerror(errno));
//    strerror(errno)

//    ret = sendto(tcp_socket, "ACK", 3, 0, (struct sockaddr*)&remote, sizeof(struct sockaddr_in));
//    printf("%s %d\n", strerror(errno), ret);
//
//    char buffer[1000] = {0};
//    ret = recv(tcp_socket, buffer, sizeof(buffer), MSG_DONTWAIT);
//    printf("%s %d\n", strerror(errno), ret);

}