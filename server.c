// server.c - threaded forwarder with IPv4/IPv6 support and logging
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
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
        if (ret < 0) {
            printf("[relay] select() error %d\n", WSAGetLastError());
            break;
        }
        if (ret == 0) continue;

        if (FD_ISSET(a, &rset)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n == 0) { printf("[relay] peer closed (socket %u)\n", (unsigned int)a); break; }
            if (n < 0) { printf("[relay] recv() err=%d\n", WSAGetLastError()); break; }
            int s = send(b, buf, n, 0);
            if (s != n) { printf("[relay] send->target failed want=%d sent=%d err=%d\n", n, s, WSAGetLastError()); break; }
            total_ab += n;
        }

        if (FD_ISSET(b, &rset)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n == 0) { printf("[relay] target closed (socket %u)\n", (unsigned int)b); break; }
            if (n < 0) { printf("[relay] recv() err=%d\n", WSAGetLastError()); break; }
            int s = send(a, buf, n, 0);
            if (s != n) { printf("[relay] send->client failed want=%d sent=%d err=%d\n", n, s, WSAGetLastError()); break; }
            total_ba += n;
        }
    }
    printf("[relay] bytes client->target: %ld, target->client: %ld\n", total_ab, total_ba);
    return 0;
}

int start_forwarder(const char *listen_port);

DWORD WINAPI handle_client(LPVOID pv) {
    SOCKET c = (SOCKET)(UINT_PTR)pv;
    unsigned char atyp;
    if (recv_all(c, (char*)&atyp, 1) <= 0) { closesocket(c); return 0; }
    printf("[server] Received ATYP: 0x%02x (%u)\n", atyp, atyp);

    unsigned short port = 0;
    SOCKET t = INVALID_SOCKET;

    if (atyp == 0x01) {
        unsigned char ip4[4];
        if (recv_all(c, (char*)ip4, 4) <= 0) { closesocket(c); return 0; }
        if (recv_all(c, (char*)&port, 2) <= 0) { closesocket(c); return 0; }
        port = ntohs(port);
        struct sockaddr_in target4;
        ZeroMemory(&target4, sizeof(target4));
        target4.sin_family = AF_INET;
        memcpy(&target4.sin_addr.s_addr, ip4, 4);
        target4.sin_port = htons(port);

        char ipstr[INET_ADDRSTRLEN]; strcpy(ipstr, inet_ntoa(target4.sin_addr));
        printf("[server] Target IPv4: %s:%u\n", ipstr, port);

        t = socket(AF_INET, SOCK_STREAM, 0);
        if (t != INVALID_SOCKET && connect(t, (struct sockaddr*)&target4, sizeof(target4)) == 0) {
            unsigned char ok = 0; send(c, (char*)&ok, 1, 0);
            printf("[server] Connected to %s:%u (IPv4)\n", ipstr, port);
            forward(c, t);
            closesocket(t);
        } else {
            unsigned char err = 1; send(c, (char*)&err, 1, 0);
            if (t != INVALID_SOCKET) closesocket(t);
            printf("[server] Connect IPv4 failed, WSA=%d\n", WSAGetLastError());
        }

    } else if (atyp == 0x04) {
        unsigned char ip6[16];
        if (recv_all(c, (char*)ip6, 16) <= 0) { closesocket(c); return 0; }
        if (recv_all(c, (char*)&port, 2) <= 0) { closesocket(c); return 0; }
        port = ntohs(port);

        struct sockaddr_in6 target6;
        ZeroMemory(&target6, sizeof(target6));
        target6.sin6_family = AF_INET6;
        memcpy(&target6.sin6_addr, ip6, 16);
        target6.sin6_port = htons(port);

        printf("[server] Target IPv6 received, port=%u\n", port);

        t = socket(AF_INET6, SOCK_STREAM, 0);
        if (t != INVALID_SOCKET && connect(t, (struct sockaddr*)&target6, sizeof(target6)) == 0) {
            unsigned char ok = 0; send(c, (char*)&ok, 1, 0);
            printf("[server] Connected to target (IPv6)\n");
            forward(c, t);
            closesocket(t);
        } else {
            unsigned char err = 1; send(c, (char*)&err, 1, 0);
            if (t != INVALID_SOCKET) closesocket(t);
            printf("[server] Connect IPv6 failed, WSA=%d\n", WSAGetLastError());
        }

    } else if (atyp == 0x03) {
        unsigned char len;
        if (recv_all(c, (char*)&len, 1) <= 0) { closesocket(c); return 0; }
        if (len == 0 || len >= 512) { closesocket(c); return 0; }
        char hostbuf[512]; ZeroMemory(hostbuf, sizeof(hostbuf));
        if (recv_all(c, hostbuf, len) <= 0) { closesocket(c); return 0; }
        hostbuf[len] = '\0';
        if (recv_all(c, (char*)&port, 2) <= 0) { closesocket(c); return 0; }
        port = ntohs(port);
        printf("[server] Target domain: %s:%u\n", hostbuf, port);

        struct addrinfo hints2, *res2, *rp;
        ZeroMemory(&hints2, sizeof(hints2));
        hints2.ai_family = AF_UNSPEC;
        hints2.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostbuf, NULL, &hints2, &res2) == 0) {
            int connected = 0;
            for (rp = res2; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET) {
                    struct sockaddr_in *sa = (struct sockaddr_in*)rp->ai_addr;
                    sa->sin_port = htons(port);
                    char ipstr[INET_ADDRSTRLEN]; strcpy(ipstr, inet_ntoa(sa->sin_addr));
                    printf("[server] DNS -> %s (IPv4)\n", ipstr);
                    t = socket(AF_INET, SOCK_STREAM, 0);
                    if (t == INVALID_SOCKET) continue;
                    if (connect(t, (struct sockaddr*)sa, sizeof(struct sockaddr_in)) == 0) {
                        unsigned char ok = 0; send(c, (char*)&ok, 1, 0);
                        printf("[server] Connected %s:%u (IPv4)\n", ipstr, port);
                        forward(c, t);
                        closesocket(t);
                        connected = 1;
                        break;
                    }
                    closesocket(t);
                } else if (rp->ai_family == AF_INET6) {
                    struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)rp->ai_addr;
                    sa6->sin6_port = htons(port);
                    printf("[server] DNS -> (IPv6)\n");
                    t = socket(AF_INET6, SOCK_STREAM, 0);
                    if (t == INVALID_SOCKET) continue;
                    if (connect(t, (struct sockaddr*)sa6, (int)rp->ai_addrlen) == 0) {
                        unsigned char ok = 0; send(c, (char*)&ok, 1, 0);
                        printf("[server] Connected (IPv6)\n");
                        forward(c, t);
                        closesocket(t);
                        connected = 1;
                        break;
                    }
                    closesocket(t);
                }
            }
            freeaddrinfo(res2);
            if (!connected) {
                unsigned char err = 1; send(c, (char*)&err, 1, 0);
                printf("[server] All connect attempts failed for %s\n", hostbuf);
            }
        } else {
            unsigned char err = 1; send(c, (char*)&err, 1, 0);
            printf("[server] DNS resolve failed for %s\n", hostbuf);
        }
    } else {
        printf("[server] ATYP unsupported 0x%02x\n", atyp);
        unsigned char err = 1; send(c, (char*)&err, 1, 0);
    }

    closesocket(c);
    printf("[server] Connection closed.\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *listen_port = "9000";
    if (argc >= 2) listen_port = argv[1];

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { printf("WSAStartup fail\n"); return 1; }

    struct addrinfo hints, *res;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, listen_port, &hints, &res) != 0) {
        printf("getaddrinfo failed\n"); WSACleanup(); return 1;
    }

    SOCKET l = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (l == INVALID_SOCKET) { printf("socket fail\n"); freeaddrinfo(res); WSACleanup(); return 1; }

    int yes = 1; setsockopt(l, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    if (bind(l, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        printf("bind fail\n"); closesocket(l); freeaddrinfo(res); WSACleanup(); return 1;
    }
    freeaddrinfo(res);

    if (listen(l, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen fail\n"); closesocket(l); WSACleanup(); return 1;
    }

    printf("[server] Forwarder listening on port %s\n", listen_port);

    while (1) {
        SOCKET c = accept(l, NULL, NULL);
        if (c == INVALID_SOCKET) {
            int err = WSAGetLastError();
            printf("[server] accept failed, err=%d\n", err);
            Sleep(100);
            continue;
        }
        printf("[server] Client connected (sock=%u)\n", (unsigned int)c);
        HANDLE h = CreateThread(NULL, 0, handle_client, (LPVOID)(UINT_PTR)c, 0, NULL);
        if (h) CloseHandle(h);
        else { printf("[server] CreateThread failed, err=%d\n", WSAGetLastError()); closesocket(c); }
    }

    closesocket(l);
    WSACleanup();
    return 0;
}