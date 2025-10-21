// server.c -- with logging
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib,"ws2_32.lib")

// Improved forward() with detailed logging. Drop-in replacement for client.c & server.c
int forward(SOCKET a, SOCKET b) {
    fd_set rset;
    char buf[8192];
    int ret;
    long total_ab=0, total_ba=0;
    struct timeval tv;
    while(1) {
        FD_ZERO(&rset);
        FD_SET(a,&rset);
        FD_SET(b,&rset);
        int nf = (int)(((a>b)?a:b) + 1);
        tv.tv_sec = 10; tv.tv_usec = 0; // timeout to periodically check
        ret = select(nf, &rset, NULL, NULL, &tv);
        if(ret < 0) {
            int err = WSAGetLastError();
            printf("[relay] select() error %d\n", err);
            break;
        }
        if(ret == 0) {
            // timeout - continue loop but log periodically
            // (avoid spamming - only if both sides alive)
            continue;
        }

        // browser/client -> remote/target
        if(FD_ISSET(a,&rset)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if(n == 0) {
                printf("[relay] peer on socket %u closed connection (recv==0)\n", (unsigned int)a);
                break;
            }
            if(n < 0) {
                int err = WSAGetLastError();
                printf("[relay] recv() from %u returned %d, WSAErr=%d\n", (unsigned int)a, n, err);
                break;
            }
            int sent = send(b, buf, n, 0);
            if(sent != n) {
                int err = (sent < 0) ? WSAGetLastError() : 0;
                printf("[relay] send() to %u failed. want=%d sent=%d WSA=%d\n", (unsigned int)b, n, sent, err);
                break;
            }
            total_ab += n;
        }

        // remote/target -> browser/client
        if(FD_ISSET(b,&rset)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if(n == 0) {
                printf("[relay] remote on socket %u closed connection (recv==0)\n", (unsigned int)b);
                break;
            }
            if(n < 0) {
                int err = WSAGetLastError();
                printf("[relay] recv() from %u returned %d, WSAErr=%d\n", (unsigned int)b, n, err);
                break;
            }
            int sent = send(a, buf, n, 0);
            if(sent != n) {
                int err = (sent < 0) ? WSAGetLastError() : 0;
                printf("[relay] send() to %u failed. want=%d sent=%d WSA=%d\n", (unsigned int)a, n, sent, err);
                break;
            }
            total_ba += n;
        }
    }

    printf("[relay] bytes client->target: %ld, target->client: %ld\n", total_ab, total_ba);
    return 0;
}

int recv_all(SOCKET s, char *buf, int len) {
    int total = 0, ret;
    while (total < len) {
        ret = recv(s, buf + total, len - total, 0);
        if (ret <= 0) return ret;
        total += ret;
    }
    return total;
}

// per-connection handler
DWORD WINAPI handle_client(LPVOID pv) {
    SOCKET c = (SOCKET)(UINT_PTR)pv;

    unsigned char atyp;
    if (recv_all(c, (char*)&atyp, 1) <= 0) { closesocket(c); return 0; }
    printf("[server] Received ATYP: 0x%02x (%u)\n", atyp, atyp);

    char hostbuf[512]; ZeroMemory(hostbuf, sizeof(hostbuf));
    struct sockaddr_in target; ZeroMemory(&target, sizeof(target));
    target.sin_family = AF_INET;
    unsigned short port;

    if (atyp == 0x01) { // IPv4
        if (recv_all(c, (char*)&target.sin_addr.s_addr, 4) <= 0) { closesocket(c); return 0; }
        if (recv_all(c, (char*)&port, 2) <= 0) { closesocket(c); return 0; }
        port = ntohs(port);
        printf("[server] Target IPv4: %s:%u\n", inet_ntoa(target.sin_addr), port);
    } else if (atyp == 0x03) { // domain
        unsigned char len;
        if (recv_all(c, (char*)&len, 1) <= 0) { closesocket(c); return 0; }
        if (len == 0 || len >= sizeof(hostbuf)) { closesocket(c); return 0; }
        if (recv_all(c, hostbuf, len) <= 0) { closesocket(c); return 0; }
        hostbuf[len] = '\0';
        if (recv_all(c, (char*)&port, 2) <= 0) { closesocket(c); return 0; }
        port = ntohs(port);
        printf("[server] Target domain: %s:%u\n", hostbuf, port);
    } else {
        printf("[server] ATYP unsupported 0x%02x\n", atyp); closesocket(c); return 0;
    }

    SOCKET t = INVALID_SOCKET;

    if (atyp == 0x01) {
        t = socket(AF_INET, SOCK_STREAM, 0);
        target.sin_port = htons(port);
        if (connect(t, (struct sockaddr*)&target, sizeof(target)) == 0) {
            unsigned char ok = 0; send(c, (char*)&ok, 1, 0);
            printf("[server] Connected to IPv4 target %s:%u\n", inet_ntoa(target.sin_addr), port);
            forward(c, t);
        } else {
            unsigned char err = 1; send(c, (char*)&err, 1, 0); closesocket(t);
            printf("[server] Connect to IPv4 failed\n");
        }
    } else { // domain
        struct addrinfo hints2, *res2, *rp;
        ZeroMemory(&hints2, sizeof(hints2));
        hints2.ai_family = AF_INET; // IPv4 only
        hints2.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostbuf, NULL, &hints2, &res2) == 0) {
            char ipstr[INET_ADDRSTRLEN];
            int connected = 0;
            for (rp = res2; rp != NULL; rp = rp->ai_next) {
                struct sockaddr_in *sa = (struct sockaddr_in*)rp->ai_addr;
                strcpy(ipstr, inet_ntoa(sa->sin_addr));
                printf("[server] DNS resolved %s -> %s\n", hostbuf, ipstr);
                sa->sin_port = htons(port);
                t = socket(AF_INET, SOCK_STREAM, 0);
                if (t == INVALID_SOCKET) continue;
                if (connect(t, (struct sockaddr*)sa, sizeof(struct sockaddr_in)) == 0) {
                    unsigned char ok = 0; send(c, (char*)&ok, 1, 0);
                    printf("[server] Connected to %s:%u\n", ipstr, port);
                    forward(c, t);
                    closesocket(t);
                    connected = 1;
                    break;
                }
                closesocket(t);
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
    }

    closesocket(c);
    printf("[server] Connection closed.\n");
    return 0;
}

// threaded server main
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
        else {
            int err = WSAGetLastError();
            printf("[server] CreateThread failed, err=%d\n", err);
            closesocket(c);
        }
    }

    closesocket(l);
    WSACleanup();
    return 0;
}
