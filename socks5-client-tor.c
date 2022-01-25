#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
//#include <netdb.h>
//#include <sys/types.h>
//#include <sys/socket.h>

int main(int argc, char **argv) {
    int sock;
    char *hostname;
    size_t len;
    struct sockaddr_in socksaddr;
    uint32_t sockshost = 0x7f000001u; /* localhost */

    if (argc == 1) {
        printf("need to provide a hostname\n");
        goto err;
    }

    hostname = argv[1];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        goto err;
    }

    // Fill the struct the old way b/c we don't want to use `getaddrinfo` and its subsequent network request!
    memset(&socksaddr, 0, sizeof(socksaddr));
    socksaddr.sin_family = AF_INET;
    socksaddr.sin_port = htons(1080);
    socksaddr.sin_addr.s_addr = htonl(sockshost);

    int res;
    if ((res = connect(sock, (struct sockaddr*) &socksaddr, sizeof(socksaddr))) == -1) {
        perror("connect");
        goto err;
    }

    // Send the first three bytes expected by the SOCKS5 protocol.
    // https://tools.ietf.org/html/rfc1928
    //
    // 0x05 = SOCKS Version.
    // 0x01 = Number of method identifier octets that appear in the next METHODS field.
    // 0x00 = In this particular case no authentication required METHOD, but the client
    //        could send a list of supported authentication methods.
    if ((res = send(sock, "\x05\x01\x00", 3, 0)) == -1) {
        perror("send");
        goto err;
    }

    // The server responds with a two octect response:
    // 1. The SOCKS version.
    // 2. The chosen authentication method among the ones sent by the client.
    char method_buf[2];
    if ((res = recv(sock, method_buf, 2, 0)) == -1) {
        perror("recv");
        goto err;
    }

    if (method_buf[0] != '\x05') {
        printf("SOCKS version is incorrect\n");
        goto err;
    }

    if (method_buf[1] != '\x00') {
        printf("SOCKS authentication method is incorrect\n");
        goto err;
    }

    len = strlen(hostname);

    if ((res = send(sock, "\x05\x01\x00\xF0", 3, 0)) == -1) {
        perror("send");
        goto err;
    }

err:
    close(sock);
    return -1;
}

