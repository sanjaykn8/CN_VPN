// server.c - Windows port of your chat server
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0x0400
#endif

#pragma comment(lib, "Ws2_32.lib")

#define BUFSIZE 1000

CRITICAL_SECTION cs;

struct client {
    char *name;
    SOCKET sock;
    struct client *next;
};

struct client *header = NULL;

/* simple safe send_all */
int send_all(SOCKET s, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, buf + sent, len - sent, 0);
        if (r == SOCKET_ERROR) return -1;
        sent += r;
    }
    return sent;
}

/* simple readline: read until '\n' (stores '\n'), returns bytes read or -1 */
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

void add_user(struct client *user) {
    user->next = header;
    header = user;
}

void delete_user_by_sock(SOCKET sock) {
    struct client *cur = header, *prev = NULL;
    while (cur) {
        if (cur->sock == sock) break;
        prev = cur;
        cur = cur->next;
    }
    if (!cur) return;
    if (prev) prev->next = cur->next;
    else header = cur->next;
    if (cur->name) free(cur->name);
    free(cur);
}

/* create listening socket on port string */
SOCKET create_listen(const char *port) {
    struct addrinfo hints, *res, *p;
    SOCKET listenfd = INVALID_SOCKET;
    int rc;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    if ((rc = getaddrinfo(NULL, port, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerrorA(rc));
        return INVALID_SOCKET;
    }
    for (p = res; p; p = p->ai_next) {
        listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listenfd == INVALID_SOCKET) continue;
        BOOL reuse = 1;
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        if (bind(listenfd, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        closesocket(listenfd);
        listenfd = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (listenfd == INVALID_SOCKET) return INVALID_SOCKET;
    if (listen(listenfd, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenfd);
        return INVALID_SOCKET;
    }
    return listenfd;
}

/* send message to all or one user */
void send_msg(SOCKET from_sock, const char *msg, const char *receiver, const char *sender) {
    char response[BUFSIZE];
    EnterCriticalSection(&cs);
    struct client *u = header;
    if (!receiver || receiver[0] == '\0') {
        while (u) {
            if (u->sock == from_sock) {
                strcpy(response, "msg sent\r\n\r\n");
                send_all(u->sock, response, (int)strlen(response));
            } else {
                snprintf(response, sizeof(response), "start\n%s:%s\r\n\r\n", sender, msg);
                send_all(u->sock, response, (int)strlen(response));
            }
            u = u->next;
        }
    } else {
        while (u) {
            if (strcmp(u->name, receiver) == 0) {
                snprintf(response, sizeof(response), "start\n%s:%s\r\n\r\n", sender, msg);
                send_all(u->sock, response, (int)strlen(response));
                strcpy(response, "msg sent\r\n\r\n");
                send_all(from_sock, response, (int)strlen(response));
                LeaveCriticalSection(&cs);
                return;
            }
            u = u->next;
        }
        strcpy(response, "user not found\r\n\r\n");
        send_all(from_sock, response, (int)strlen(response));
    }
    LeaveCriticalSection(&cs);
}

void evaluate(const char *buf_in, SOCKET sock, const char *username) {
    char response[BUFSIZE];
    char msg[BUFSIZE] = {0};
    char receiver[BUFSIZE] = {0};
    char keyword[BUFSIZE] = {0};
    if (strcmp(buf_in, "help\n") == 0 || strcmp(buf_in, "help\r\n")==0) {
        snprintf(response, sizeof(response),
                 "msg \"text\" : send the msg to all the clients online\n"
                 "msg \"text\" user :send the msg to a particular client\n"
                 "online : get the username of all the clients online\n"
                 "quit : exit the chatroom\r\n\r\n");
        send_all(sock, response, (int)strlen(response));
        return;
    }
    if (strcmp(buf_in, "online\n") == 0 || strcmp(buf_in, "online\r\n")==0) {
        response[0]='\0';
        EnterCriticalSection(&cs);
        struct client *u = header;
        while (u) {
            strncat(response, u->name, sizeof(response) - strlen(response) - 2);
            strncat(response, "\n", sizeof(response) - strlen(response) - 1);
            u = u->next;
        }
        LeaveCriticalSection(&cs);
        strncat(response, "\r\n", sizeof(response)-strlen(response)-1);
        send_all(sock, response, (int)strlen(response));
        return;
    }
    if (strcmp(buf_in, "quit\n") == 0 || strcmp(buf_in, "quit\r\n")==0) {
        EnterCriticalSection(&cs);
        delete_user_by_sock(sock);
        LeaveCriticalSection(&cs);
        strcpy(response, "exit");
        send_all(sock, response, (int)strlen(response));
        closesocket(sock);
        return;
    }

    // parse: keyword " message " receiver
    // basic sscanf adapted for newline-terminated string
    // Expecting: msg "text" username
    if (sscanf(buf_in, "%s \" %[^\"] \" %s", keyword, msg, receiver) < 1) {
        strcpy(response, "Invalid command\r\n\r\n");
        send_all(sock, response, (int)strlen(response));
        return;
    }
    if (strcmp(keyword, "msg") == 0) {
        EnterCriticalSection(&cs);
        send_msg(sock, msg, strlen(receiver) ? receiver : NULL, username);
        LeaveCriticalSection(&cs);
    } else {
        strcpy(response, "Invalid command\r\n\r\n");
        send_all(sock, response, (int)strlen(response));
    }
}

/* thread routine */
DWORD WINAPI client_handler(LPVOID arg) {
    SOCKET client_sock = (SOCKET)(UINT_PTR)arg;
    char username[BUFSIZE];
    int n;

    n = recv_line(client_sock, username, BUFSIZE);
    if (n <= 0) { closesocket(client_sock); return 0; }
    // strip newline
    if (username[n-1]=='\n') username[n-1] = '\0';
    if (n>1 && username[n-2]=='\r') username[n-2]='\0';

    struct client *u = (struct client*)malloc(sizeof(*u));
    u->name = _strdup(username);
    u->sock = client_sock;
    u->next = NULL;

    EnterCriticalSection(&cs);
    add_user(u);
    LeaveCriticalSection(&cs);

    char buf[BUFSIZE];
    while (1) {
        int r = recv_line(client_sock, buf, BUFSIZE);
        if (r <= 0) break;
        // ensure null-terminated
        // pass raw line to evaluate
        evaluate(buf, client_sock, u->name);
    }

    EnterCriticalSection(&cs);
    delete_user_by_sock(client_sock);
    LeaveCriticalSection(&cs);
    closesocket(client_sock);
    return 0;
}

int main(int argc, char **argv) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n"); return 1;
    }
    InitializeCriticalSection(&cs);

    const char *port = "80";
    if (argc > 1) port = argv[1];

    SOCKET listenfd = create_listen(port);
    if (listenfd == INVALID_SOCKET) {
        fprintf(stderr, "create_listen failed\n"); return 1;
    }

    printf("waiting on port %s\n", port);

    while (1) {
        struct sockaddr_storage clientaddr;
        int clientlen = sizeof(clientaddr);
        SOCKET *clientsock = malloc(sizeof(SOCKET));
        if (!clientsock) continue;
        *clientsock = accept(listenfd, (struct sockaddr*)&clientaddr, &clientlen);
        if (*clientsock == INVALID_SOCKET) {
            free(clientsock);
            continue;
        }
        printf("A new client connected\n");
        CreateThread(NULL, 0, client_handler, (LPVOID)(UINT_PTR)(*clientsock), 0, NULL);
        // free(clientsock) intentionally not here; we used value only
    }

    DeleteCriticalSection(&cs);
    closesocket(listenfd);
    WSACleanup();
    return 0;
}
