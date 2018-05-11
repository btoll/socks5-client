#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <assert.h>
#include "socks5_client.h"

// SOCKS5 RFC
// https://tools.ietf.org/html/rfc1928

int recv_data(int fd, char *buf, int count, int log) {
    uint8_t retv;

//    TRACE_MSG(log);

    if ((retv = recv(fd, buf, count, 0)) == -1)
        return -1;

    DEBUG(log, "recv_data: retv = %d\n", retv);
    assert(retv > 0);

    return retv;
}

int send_data(int fd, char *buf, int count, int log) {
    uint8_t retv;

    if ((retv = send(fd, buf, count, 0)) == -1)
        return -1;

    DEBUG(log, "send_data: retv = %d\n", retv);
    assert(retv > 0);

    return retv;
}

int socks5_connect(struct connection *conn) {
    struct sockaddr_in socksaddr;

    memset(&socksaddr, 0, sizeof(socksaddr));
    socksaddr.sin_family = AF_INET;
    socksaddr.sin_port = htons(conn->addr.host.port);
    // We'll always assume proxy is on localhost!
    socksaddr.sin_addr.s_addr = htonl(SOCKS5_HOST);
    memset(socksaddr.sin_zero, '\0', sizeof(socksaddr.sin_zero));

    if (connect(conn->fd, (struct sockaddr *) &socksaddr, sizeof(socksaddr)))
        return -1;

    return 0;
}

int socks5_send_method(struct connection *conn, int log) {
    struct socks5_method_request req;
    // TODO: See TODO below about number of supported methods!
    char buf[3];

    memset(&req, 0, sizeof(req));

    // Let's start the handshake.  The client sends three bytes:
    // 1. Socks version.
    // 2. Number of methods.
    // 3. Authentication methods supported (in this case 0x00 == none).

    req.ver = SOCKS5_VERSION;
    req.nmethods = '\x01';
    req.methods = '\x00';

    memcpy(buf, &req, sizeof(req));

    DEBUG(log, "function %s -> send_data\n", __FUNCTION__);

    // TODO: Hardcode the number of bytes?  This only works if there's never any more
    // supported authentication methods than 1 (no auth)!
    return send_data(conn->fd, buf, 3, log);
}

int socks5_recv_method(struct connection *conn, int log) {
    // The response should return two bytes:
    // 1. Socks version.
    // 2. Authentication method picked by server from among those sent by client.
    char method_buf[2];

    DEBUG(log, "function %s -> recv_data\n", __FUNCTION__);

    if (recv_data(conn->fd, method_buf, 2, log) != 2)
        return -1;

    assert(method_buf[0] == SOCKS5_VERSION);
    assert(method_buf[1] == '\x00');

    if (method_buf[0] != SOCKS5_VERSION) {
        fprintf(stderr, "socks5 version failure");
        return -1;
    }

    if (method_buf[1] != '\x00') {
        fprintf(stderr, "socks5 authentication method mismatch");
        return -1;
    }

    return 0;
}

int socks5_send_connect_request(struct connection *conn, int log) {
    char buf[1500];                             // MTU.
    struct socks5_request socksreq;
    uint16_t buf_len = sizeof(socksreq);

    memset(&buf, 0, sizeof(buf));
    memset(&socksreq, 0, sizeof(socksreq));

    socksreq.ver = SOCKS5_VERSION;
    // TODO
    socksreq.cmd = (conn->addr.host.port == 9050 && conn->addr.domain == CONNECTION_DOMAIN_NAME) ?
        '\xF0' :                      // '\xF0' Tor-specific RESOLVE cmd.
        '\x01';                       // CONNECT cmd.
//        '\x02';                       // BIND cmd.
//        '\x03';                       // UDP associate.

    socksreq.rsv = '\x00';      // Always 0x00.

    switch (conn->addr.domain) {
    case CONNECTION_DOMAIN_INET:
        {
            // TODO
            struct socks5_request_ipv4 req_ipv4;

            socksreq.atyp = ATYP_IPV4;
            // Copy the first part of the request.
            memcpy(buf, &socksreq, sizeof(socksreq));

            memset(&req_ipv4, 0, sizeof(req_ipv4));

            inet_pton(AF_INET, conn->addr.host.ip, req_ipv4.addr);

            // TODO: Hardcode for now.
            req_ipv4.port = htons(80);

            memcpy(buf + buf_len, &req_ipv4, sizeof(req_ipv4));
            buf_len += sizeof(req_ipv4);

            DEBUG(log, "buf_len %d\n", buf_len);
            break;
        }
    case CONNECTION_DOMAIN_INET6:
        {
            // TODO
            socksreq.atyp = ATYP_IPV6;
            memcpy(buf, &socksreq, sizeof(socksreq));

            DEBUG(log, "buf_len %d\n", buf_len);
            break;
        }
    case CONNECTION_DOMAIN_NAME:
        {
            struct socks5_request_domain req_domain;

            socksreq.atyp = ATYP_DOMAIN;
            // Copy the first part of the request.
            memcpy(buf, &socksreq, sizeof(socksreq));

            memset(&req_domain, 0, sizeof(req_domain));

            req_domain.len = strlen(conn->addr.host.domain);
            memcpy(req_domain.name, conn->addr.host.domain, req_domain.len);
            req_domain.port = htons(80);        // TODO: Don't hardcode!

            // Start copying the contents of the `socks5_request_domain` struct after the memory that holds the contents of the `socks5_request` struct.
            memcpy(buf + buf_len, &req_domain.len, sizeof(req_domain.len));
            buf_len += sizeof(req_domain.len);

            // Only copy the length of the hostname, not the size of the struct field (no terminating NUL byte).
            memcpy(buf + buf_len, &req_domain.name, req_domain.len);
            buf_len += req_domain.len;

            memcpy(buf + buf_len, &req_domain.port, sizeof(req_domain.port));
            buf_len += sizeof(req_domain.port);
            buf[buf_len] = '\0';

            int n = 0;
            while (n < 18) {
                printf("%d\n", buf[n++]);
            }

            /*
             * Example of DNS resolution:
             *
             *      buf =
             *          \0x05
             *          \0x03 or \0xF0
             *          \0x00
             *          \0x03
             *
             *          \0x10
             *          benjamintoll.com
             *          80
             */
            break;
        }
    default:
        break;
    }

    DEBUG(log, "function %s -> send_data\n", __FUNCTION__);

    return send_data(conn->fd, buf, buf_len, log);
}

void usage() {
    puts("Usage: socks5-client [-v] [-4] [-6] [-p port] [-h hostname]");
    exit(1);
}

int main(int argc, char **argv) {
    struct connection conn;
    uint8_t n_args = argc - 1, log = 0;
    uint16_t sock;
    uint32_t sockshost = 0x7f000001u;           // Hardcode localhost for now.
    char **arg;
    char *err_msg = malloc(255);

    memset(&err_msg, 0, sizeof(err_msg));

    if (n_args == 0) {
        usage();
        goto err;
    }

    memset(&conn, 0, sizeof(conn));
    memset(&conn.addr.host.domain, 0, sizeof(conn.addr.host.domain));

    arg = &argv[1];

    // Default to port 1080, default for SOCKS*.
    conn.addr.host.port = 1080;

    while (n_args && *arg[0] == '-') {
        if (!strncmp("-4", *arg, 2)) {
            conn.addr.domain = CONNECTION_DOMAIN_INET;
            conn.addr.host.ip = arg[1];

            arg += 2;
            n_args -= 2;
        } else if (!strncmp("-6", *arg, 2)) {
            conn.addr.domain = CONNECTION_DOMAIN_INET6;
            conn.addr.host.ip = arg[1];

            arg += 2;
            n_args -= 2;
        } else if (!strncmp("-h", *arg, 2)) {
            conn.addr.domain = CONNECTION_DOMAIN_NAME;
            conn.addr.host.domain = arg[1];

            arg += 2;
            n_args -= 2;
        } else if (!strncmp("-p", *arg, 2)) {
            conn.addr.host.port = atoi(arg[1]);

            arg += 2;
            n_args -= 2;
        } else if (!strncmp("-v", *arg, 2)) {
            log = 1;

            arg += 1;
            n_args -= 1;
        } else {
            printf("Unrecognized flag\n");
        }
    }

    DEBUG(log, "domain %d\n", conn.addr.domain);
    DEBUG(log, "socks host %d\n", sockshost);
    DEBUG(log, "socks port %d\n", conn.addr.host.port);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
    }

    conn.fd = sock;

    DEBUG(log, "sock fd = %d\n", sock);

    assert(sock);
    assert(sock > 2);

    if (socks5_connect(&conn) == -1) {
        err_msg = "connect";
        goto err;
    }

    if (socks5_send_method(&conn, log) == -1) {
        err_msg = "send";
        goto err;
    }

    if (socks5_recv_method(&conn, log) == -1) {
        err_msg = "recv";
        goto err;
    }

    if (socks5_send_connect_request(&conn, log) == -1) {
        err_msg = "connect_request";
        goto err;
    }

    char buf[16];
    memset(&buf, 0, 16);

    if (recv_data(conn.fd, buf, 4, log) != 4) {
        err_msg = "recv_request";
        goto err;
    }

    printf("buf[0] %d\n", buf[0]);
    printf("buf[1] %d\n", buf[1]);
    printf("buf[2] %d\n", buf[2]);
    printf("buf[3] %d\n", buf[3]);

    if (buf[0] != '\x05') {
        err_msg = "bad SOCKS5 reply version";
        goto err;
    }

    if (buf[1] != '\x00') {
        err_msg = "unsuccessful";
        goto err;
    }

    // TODO: IPv6 address and hostname.

    if (buf[3] == '\x01') {             // IPv4 address.
        // We need to make another request, per the RESOLVE command, to get the resolved IP address.
        if (recv_data(conn.fd, buf, 4, log) != 4) {
            err_msg = "recv_request";
            goto err;
        }

//        printf("%d\n", buf[0]);
//        printf("%d\n", buf[1]);
//        printf("%d\n", buf[2]);
//        printf("%d\n", buf[3]);

        // TODO: Use sockaddr_storage instead! (Handles both IPv4 and IPv6 so no need to anticipate which one is needed.)
        struct sockaddr_in si;
        memset(&si, 0, sizeof(struct sockaddr_in));

        si.sin_family = AF_INET;
        si.sin_addr.s_addr = *(uint32_t *) buf;         // Same as `memcpy(&ip, buf, 4)`.

        char ipstring[32];
        memset(ipstring, 0, 32);
        inet_ntop(AF_INET, &si.sin_addr, ipstring, 32);

        printf("%s\n", ipstring);
    }

    free(err_msg);

    return 0;

err:
    perror(err_msg);
    free(err_msg);
    return -1;
}

