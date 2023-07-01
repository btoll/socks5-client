#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#define DEBUG(log, fmt, ...) if (log) printf("DEBUG -> " fmt, __VA_ARGS__)
#define TRACE_MSG(log) if (log) fprintf(stderr, "TRACE: %s() [%s:%d]\n", __FUNCTION__, __FILE__, __LINE__)

#define ATYP_IPV4 1
#define ATYP_DOMAIN 3
#define ATYP_IPV6 4

#define SOCKS5_VERSION 5
#define SOCKS5_HOST 0x7f000001u           // Localhost.

enum connection_domain {
    CONNECTION_DOMAIN_INET  = 1,
    CONNECTION_DOMAIN_INET6 = 2,
    CONNECTION_DOMAIN_NAME  = 3,
};

struct connection_addr {
    enum connection_domain domain;

    struct {
        char *domain;
        char *ip;
        uint16_t port;
    } host;
};

struct connection {
    int fd;
    struct connection_addr addr;
};

struct socks5_method_request {
    uint8_t ver;                                // Socks5 version.
    uint8_t nmethods;                           // Socks5 number of authentication methods supported.
//    uint8_t methods[3];                         // Socks5 authentication methods supported.
    // TODO: Only works when there's only 1 supported authentication method (none)!
    uint8_t methods;                            // Socks5 authentication methods supported.
};

struct socks5_request {
    uint8_t ver;                                // Socks5 version (in this case always 0x05).
    uint8_t cmd;                                // Socks5 cmd (depends on type of socks proxy, i.e., Tor can be RESOLVE for DNS).
    uint8_t rsv;                                // Socks5 reserved (always 0x00).
    uint8_t atyp;                               // Socks5 atyp (domain name).
};

struct socks5_request_ipv4 {
    uint8_t addr[4];
    uint16_t port;
};

struct socks5_request_ipv6 {
    uint8_t addr[16];
    uint16_t port;
};

struct socks5_request_domain {
    uint8_t len;
    unsigned char name[UINT8_MAX];
    uint16_t port;
};

int send_data(int fd, char *buf, int buf_len, int log);
int recv_data(int fd, char *buf, int buf_len, int log);
int socks5_connect(struct connection *conn);
int socks5_send_method(struct connection *conn, int log);
int socks5_recv_method(struct connection *conn, int log);
int socks5_send_connect_request(struct connection *conn, int log);

#endif /* SOCKS5_CLIENT_H */

