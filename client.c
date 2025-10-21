// client.c -- local SOCKS5 with logging
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
    int got=0;
    while(got < len) {
        int r = recv(s, buf+got, len-got, 0);
        if(r<=0) return r;
        got += r;
    }
    return got;
}

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

int start_socks_listener(const char *remote_ip, const char *remote_port) {
    WSADATA wsa; if(WSAStartup(MAKEWORD(2,2), &wsa)!=0){ printf("WSAStartup fail\n"); return 1; }

    struct addrinfo hints, *res;
    ZeroMemory(&hints,sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if(getaddrinfo("127.0.0.1", "1080", &hints, &res)!=0){ printf("getaddrinfo local fail\n"); return 1; }
    SOCKET l = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(bind(l, res->ai_addr, (int)res->ai_addrlen)==SOCKET_ERROR){ printf("bind local fail\n"); return 1; }
    if(listen(l,5)==SOCKET_ERROR){ printf("listen fail\n"); return 1; }
    printf("[client] SOCKS5 listening on 127.0.0.1:1080\n");

    while(1) {
        SOCKET s = accept(l, NULL, NULL);
        if(s==INVALID_SOCKET) break;
        printf("[client] Browser connected.\n");

        unsigned char ver;
        if(recv_all(s, (char*)&ver, 1)<=0){ closesocket(s); continue; }
        if(ver != 0x05){ closesocket(s); continue; }
        unsigned char nmethods;
        if(recv_all(s, (char*)&nmethods, 1)<=0){ closesocket(s); continue; }
        char methods[256];
        if(recv_all(s, methods, nmethods) <= 0){ closesocket(s); continue; }
        unsigned char reply[2] = {0x05, 0x00}; // no auth
        send(s, (char*)reply, 2, 0);

        unsigned char req[4];
        if(recv_all(s, (char*)req, 4) <= 0){ closesocket(s); continue; }
        if(req[1] != 0x01){ // only CONNECT
            unsigned char rep[10] = {0x05,0x07,0x00,0x01,0,0,0,0,0,0};
            send(s,(char*)rep,10,0); closesocket(s); continue;
        }
        unsigned char atyp = req[3];
        char hostbuf[512]; ZeroMemory(hostbuf,sizeof(hostbuf));
        unsigned char ip4[4];
        unsigned short dstport;
        if(atyp==0x01) {
            if(recv_all(s, (char*)ip4, 4) <=0){ closesocket(s); continue; }
            if(recv_all(s, (char*)&dstport, 2) <=0){ closesocket(s); continue; }
            dstport = ntohs(dstport);
            printf("[client] Request target IPv4: %u.%u.%u.%u:%u\n", ip4[0], ip4[1], ip4[2], ip4[3], dstport);
        } else if(atyp==0x03) {
            unsigned char len;
            if(recv_all(s, (char*)&len, 1) <=0){ closesocket(s); continue; }
            if(recv_all(s, hostbuf, len) <=0){ closesocket(s); continue; }
            hostbuf[len]=0;
            if(recv_all(s, (char*)&dstport, 2) <=0){ closesocket(s); continue; }
            dstport = ntohs(dstport);
            printf("[client] Request target domain: %s:%u\n", hostbuf, dstport);
        } else {
            unsigned char rep[10] = {0x05,0x08,0x00,0x01,0,0,0,0,0,0};
            send(s,(char*)rep,10,0); closesocket(s); continue;
        }

        // Connect to remote forwarder
        struct addrinfo rhints, *rres;
        ZeroMemory(&rhints,sizeof(rhints));
        rhints.ai_family = AF_UNSPEC;
        rhints.ai_socktype = SOCK_STREAM;
        if(getaddrinfo(remote_ip, remote_port, &rhints, &rres)!=0){ printf("[client] resolve remote fail\n"); closesocket(s); continue; }
        SOCKET r = socket(rres->ai_family, rres->ai_socktype, rres->ai_protocol);
        char rip[128]="?";
        ((struct sockaddr_in*)rres->ai_addr)->sin_addr.S_un.S_addr; /* no-op to avoid unused */
        if(connect(r, rres->ai_addr, (int)rres->ai_addrlen)==SOCKET_ERROR){
            printf("[client] connect remote fail\n");
            // send SOCKS5 connection failure back to browser
            unsigned char rep_fail[10] = {0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0};
            send(s, (char*)rep_fail, 10, 0);
            closesocket(s);
            closesocket(r);
            freeaddrinfo(rres);
            continue;
        }
        // get remote peer ip string if IPv4
        if(rres->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in*)rres->ai_addr;
            strncpy(rip, inet_ntoa(sa->sin_addr), sizeof(rip)-1);
        }
        freeaddrinfo(rres);
        printf("[client] Connected to forwarder %s:%s\n", remote_ip, remote_port);

        // send destination info to remote using our mini-protocol
        if(atyp==0x01) {
            unsigned char buf[1+4+2];
            buf[0]=0x01;
            memcpy(buf+1, ip4, 4);
            unsigned short p = htons(dstport);
            memcpy(buf+5, &p, 2);
            send(r, (char*)buf, sizeof(buf), 0);
            printf("[client] Sent IPv4 destination to forwarder\n");
        } else {
            unsigned char len = (unsigned char)strlen(hostbuf);
            int sz = 1 + 1 + len + 2;
            char *buf = (char*)malloc(sz);
            buf[0]=0x03;
            buf[1]=len;
            memcpy(buf+2, hostbuf, len);
            unsigned short p = htons(dstport);
            memcpy(buf+2+len, &p, 2);
            send(r, buf, sz, 0);
            printf("[client] Sent domain destination '%s' to forwarder\n", hostbuf);
            free(buf);
        }
        // wait reply byte
        unsigned char ok;
        if(recv_all(r, (char*)&ok, 1) <= 0){ printf("[client] remote reply read fail\n"); closesocket(s); closesocket(r); continue; }
        printf("[client] Forwarder reply: 0x%02x (%u)\n", ok, ok);
        if(ok != 0) {
            unsigned char rep[10] = {0x05,0x05,0x00,0x01,0,0,0,0,0,0};
            send(s,(char*)rep,10,0); closesocket(s); closesocket(r); continue;
        }
        // Reply success to browser
        unsigned char rep[10] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
        send(s,(char*)rep,10,0);
        printf("[client] SOCKS CONNECT succeeded. Starting relay.\n");

        forward(s,r);

        closesocket(s);
        closesocket(r);
        printf("[client] Session closed.\n");
    }
    closesocket(l);
    WSACleanup();
    return 0;
}

int main(int argc, char *argv[]) {
    if(argc != 3) {
        printf("Usage: %s <remote_forwarder_ip> <remote_forwarder_port>\n", argv[0]);
        return 1;
    }
    return start_socks_listener(argv[1], argv[2]);
}