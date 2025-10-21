// client.c - Windows port of your chat client
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define MAXLINE 1024
char prompt[] = "Chatroom> ";

int send_all(SOCKET s, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, buf + sent, len - sent, 0);
        if (r == SOCKET_ERROR) return -1;
        sent += r;
    }
    return sent;
}

int recv_line(SOCKET s, char *out, int maxlen) {
    int total = 0;
    char c;
    while (total < maxlen - 1) {
        int r = recv(s, &c, 1, 0);
        if (r <= 0) return -1;
        out[total++] = c;
        if (c == '\n') break;
    }
    out[total] = '\0';
    return total;
}

SOCKET connect_to(const char *host, const char *port) {
    struct addrinfo hints, *res, *p;
    SOCKET s = INVALID_SOCKET;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return INVALID_SOCKET;
    for (p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

DWORD WINAPI reader_thread(LPVOID arg) {
    SOCKET s = (SOCKET)(UINT_PTR)arg;
    char buf[MAXLINE];
    while (1) {
        int r = recv_line(s, buf, MAXLINE);
        if (r <= 0) break;
        if (strcmp(buf, "exit") == 0) {
            closesocket(s);
            exit(0);
        }
        if (strcmp(buf, "start\n") == 0 || strcmp(buf, "start\r\n")==0) {
            printf("\n");
        } else {
            printf("%s", buf);
        }
        // read until blank line
        while (1) {
            int r2 = recv_line(s, buf, MAXLINE);
            if (r2 <= 0) break;
            if (strcmp(buf, "\r\n") == 0 || strcmp(buf, "\n")==0) break;
            if (strcmp(buf, "exit") == 0) { closesocket(s); exit(0); }
            printf("%s", buf);
        }
        printf("%s", prompt);
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char **argv) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { fprintf(stderr,"WSAStartup failed\n"); return 1; }

    const char *address = NULL, *port = NULL, *username = NULL;
    int i;
    // simple argument parsing: -a addr -p port -u username
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i+1 < argc) { address = argv[++i]; continue; }
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc) { port = argv[++i]; continue; }
        if (strcmp(argv[i], "-u") == 0 && i+1 < argc) { username = argv[++i]; continue; }
        if (strcmp(argv[i], "-h") == 0) { printf("usage: -a address -p port -u username\n"); return 0; }
    }
    if (!address || !port || !username) {
        printf("Invalid usage. Example: chat_client.exe -a 127.0.0.1 -p 80 -u alice\n"); return 1;
    }

    SOCKET s = connect_to(address, port);
    if (s == INVALID_SOCKET) { printf("Couldn't connect to server\n"); return 1; }

    // send username + newline
    char un[MAXLINE];
    snprintf(un, sizeof(un), "%s\n", username);
    if (send_all(s, un, (int)strlen(un)) == -1) { printf("send failed\n"); closesocket(s); return 1; }

    CreateThread(NULL, 0, reader_thread, (LPVOID)(UINT_PTR)s, 0, NULL);

    char line[MAXLINE];
    printf("%s", prompt);
    fflush(stdout);
    while (fgets(line, sizeof(line), stdin)) {
        if (send_all(s, line, (int)strlen(line)) == -1) {
            printf("send error\n");
            closesocket(s);
            return 1;
        }
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
