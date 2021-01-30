#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

int main(int argc, char **argv) {
    int status;
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];

    if (argc == 1) {
        fprintf(stderr, "usage: %s hostname\n", argv[0]);
        goto err;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(argv[1], NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        goto err;
    }

    // `res` now points to a linked list of one or more struct `addrinfo`s.

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;

        struct sockaddr_in *ipv4 = (struct sockaddr_in *) p->ai_addr;
        addr = &(ipv4->sin_addr);

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("  %s\n", ipstr);
    }

    freeaddrinfo(res);                              // Free the linked list.

    return 0;

err:
    return -1;
}

