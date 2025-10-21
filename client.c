// client.c - local SOCKS5 listener with IPv6 support and logging
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib,"ws2_32.lib")

int recv_all(SOCKET s, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int r = recv(s, buf + got, len - got, 0);
        if (r <= 0) return r;
        got += r;
    }
    return got;
}

int forward(SOCKET a, SOCKET b) {
    fd_set rset;
    char buf[8192];
    int ret;
    long total_ab = 0, total_ba = 0;
    struct timeval tv;
    while (1) {
        FD_ZERO(&rset);
        FD_SET(a, &rset);
        FD_SET(b, &rset);
        int nf = (int)(((a > b) ? a : b) + 1);
        tv.tv_sec = 10; tv.tv_usec = 0;
        ret = select(nf, &rset, NULL, NULL, &tv);
        if (ret < 0) { printf("[relay] select err=%d\n", WSAGetLastError()); break; }
        if (ret == 0) continue;

        if (FD_ISSET(a, &rset)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n == 0) { printf("[relay] browser closed\n"); break; }
            if (n < 0) { printf("[relay] recv err=%d\n", WSAGetLastError()); break; }
            int s = send(b, buf, n, 0);
            if (s != n) { printf("[relay] send->remote failed want=%d sent=%d err=%d\n", n, s, WSAGetLastError()); break; }
            total_ab += n;
        }
        if (FD_ISSET(b, &rset)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n == 0) { printf("[relay] remote closed\n"); break; }
            if (n < 0) { printf("[relay] recv err=%d\n", WSAGetLastError()); break; }
            int s = send(a, buf, n, 0);
            if (s != n) { printf("[relay] send->browser failed want=%d sent=%d err=%d\n", n, s, WSAGetLastError()); break; }
            total_ba += n;
        }
    }
    printf("[relay] bytes browser->remote: %ld, remote->browser: %ld\n", total_ab, total_ba);
    return 0;
}

int start_socks_listener(const char *remote_ip, const char *remote_port) {
    WSADATA wsa; if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { printf("WSAStartup fail\n"); return 1; }

    struct addrinfo hints, *res;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo("127.0.0.1", "1080", &hints, &res) != 0) { printf("getaddrinfo local fail\n"); return 1; }
    SOCKET l = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (l == INVALID_SOCKET) { printf("socket fail\n"); return 1; }
    if (bind(l, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) { printf("bind local fail\n"); return 1; }
    freeaddrinfo(res);
    if (listen(l, 5) == SOCKET_ERROR) { printf("listen fail\n"); return 1; }
    printf("[client] SOCKS5 listening on 127.0.0.1:1080\n");

    while (1) {
        SOCKET s = accept(l, NULL, NULL);
        if (s == INVALID_SOCKET) break;
        printf("[client] Browser connected.\n");

        unsigned char ver;
        if (recv_all(s, (char*)&ver, 1) <= 0) { closesocket(s); continue; }
        if (ver != 0x05) { closesocket(s); continue; }
        unsigned char nmethods;
        if (recv_all(s, (char*)&nmethods, 1) <= 0) { closesocket(s); continue; }
        char methods[256];
        if (recv_all(s, methods, nmethods) <= 0) { closesocket(s); continue; }
        unsigned char reply[2] = {0x05, 0x00}; send(s, (char*)reply, 2, 0);

        unsigned char req[4];
        if (recv_all(s, (char*)req, 4) <= 0) { closesocket(s); continue; }
        if (req[1] != 0x01) { unsigned char rep[10] = {0x05,0x07,0x00,0x01,0,0,0,0,0,0}; send(s, (char*)rep, 10, 0); closesocket(s); continue; }
        unsigned char atyp = req[3];

        char hostbuf[512]; ZeroMemory(hostbuf, sizeof(hostbuf));
        unsigned char ip4[4];
        unsigned char ip6[16];
        unsigned short dstport = 0;

        if (atyp == 0x01) {
            if (recv_all(s, (char*)ip4, 4) <= 0) { closesocket(s); continue; }
            if (recv_all(s, (char*)&dstport, 2) <= 0) { closesocket(s); continue; }
            dstport = ntohs(dstport);
            printf("[client] Request target IPv4: %u.%u.%u.%u:%u\n", ip4[0], ip4[1], ip4[2], ip4[3], dstport);

        } else if (atyp == 0x03) {
            unsigned char len;
            if (recv_all(s, (char*)&len, 1) <= 0) { closesocket(s); continue; }
            if (recv_all(s, hostbuf, len) <= 0) { closesocket(s); continue; }
            hostbuf[len] = 0;
            if (recv_all(s, (char*)&dstport, 2) <= 0) { closesocket(s); continue; }
            dstport = ntohs(dstport);
            printf("[client] Request target domain: %s:%u\n", hostbuf, dstport);

        } else if (atyp == 0x04) {
            if (recv_all(s, (char*)ip6, 16) <= 0) { closesocket(s); continue; }
            if (recv_all(s, (char*)&dstport, 2) <= 0) { closesocket(s); continue; }
            dstport = ntohs(dstport);
            printf("[client] Request target IPv6 (raw bytes) port=%u\n", dstport);

        } else {
            unsigned char rep[10] = {0x05,0x08,0x00,0x01,0,0,0,0,0,0};
            send(s, (char*)rep, 10, 0);
            closesocket(s);
            continue;
        }

        // connect to forwarder
        struct addrinfo rhints, *rres;
        ZeroMemory(&rhints, sizeof(rhints));
        rhints.ai_family = AF_UNSPEC;
        rhints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(remote_ip, remote_port, &rhints, &rres) != 0) { printf("[client] resolve remote fail\n"); closesocket(s); continue; }

        SOCKET r = INVALID_SOCKET;
        struct addrinfo *rp;
        for (rp = rres; rp != NULL; rp = rp->ai_next) {
            r = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (r == INVALID_SOCKET) continue;
            if (connect(r, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
            closesocket(r);
            r = INVALID_SOCKET;
        }
        if (r == INVALID_SOCKET) {
            printf("[client] connect remote fail\n");
            unsigned char rep_fail[10] = {0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0};
            send(s, (char*)rep_fail, 10, 0);
            freeaddrinfo(rres);
            closesocket(s);
            continue;
        }
        freeaddrinfo(rres);
        printf("[client] Connected to forwarder %s:%s\n", remote_ip, remote_port);

        // send mini-protocol to forwarder: 0x01 IPv4, 0x03 domain, 0x04 IPv6
        if (atyp == 0x01) {
            unsigned char buf[1+4+2];
            buf[0] = 0x01;
            memcpy(buf+1, ip4, 4);
            unsigned short p = htons(dstport);
            memcpy(buf+5, &p, 2);
            send(r, (char*)buf, sizeof(buf), 0);
            printf("[client] Sent IPv4 destination to forwarder\n");
        } else if (atyp == 0x03) {
            unsigned char len = (unsigned char)strlen(hostbuf);
            int sz = 1 + 1 + len + 2;
            char *buf = (char*)malloc(sz);
            buf[0] = 0x03;
            buf[1] = len;
            memcpy(buf+2, hostbuf, len);
            unsigned short p = htons(dstport);
            memcpy(buf+2+len, &p, 2);
            send(r, buf, sz, 0);
            printf("[client] Sent domain destination '%s' to forwarder\n", hostbuf);
            free(buf);
        } else { // atyp == 0x04
            unsigned char buf[1 + 16 + 2];
            buf[0] = 0x04;
            memcpy(buf+1, ip6, 16);
            unsigned short p = htons(dstport);
            memcpy(buf+1+16, &p, 2);
            send(r, (char*)buf, sizeof(buf), 0);
            printf("[client] Sent IPv6 destination (16 bytes) to forwarder\n");
        }

        unsigned char ok;
        if (recv_all(r, (char*)&ok, 1) <= 0) { printf("[client] remote reply read fail\n"); closesocket(s); closesocket(r); continue; }
        printf("[client] Forwarder reply: 0x%02x (%u)\n", ok, ok);
        if (ok != 0) {
            unsigned char rep[10] = {0x05,0x05,0x00,0x01,0,0,0,0,0,0};
            send(s, (char*)rep, 10, 0);
            closesocket(s); closesocket(r);
            continue;
        }

        unsigned char rep_ok[10] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
        send(s, (char*)rep_ok, 10, 0);
        printf("[client] SOCKS CONNECT succeeded. Starting relay.\n");

        forward(s, r);

        closesocket(s);
        closesocket(r);
        printf("[client] Session closed.\n");
    }

    closesocket(l);
    WSACleanup();
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) { printf("Usage: %s <forwarder_ip> <forwarder_port>\n", argv[0]); return 1; }
    return start_socks_listener(argv[1], argv[2]);
}
