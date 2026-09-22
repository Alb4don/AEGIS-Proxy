
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

typedef const char *(*version_fn)(void);
typedef int         (*start_fn)(void);
typedef void        (*stop_fn)(void);
typedef int         (*running_fn)(void);
typedef int         (*config_fn)(int, const char *, int, int);

static int probe_port(unsigned short port)
{
    WSADATA w;
    SOCKET s;
    struct sockaddr_in a;
    u_long nb = 1;
    fd_set wset;
    struct timeval tv;
    int r, err, l;

    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return 0;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return 0; }
    ioctlsocket(s, FIONBIO, &nb);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    r = connect(s, (struct sockaddr *)&a, sizeof a);
    if (r != 0) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); WSACleanup(); return 0; }
        FD_ZERO(&wset); FD_SET(s, &wset);
        tv.tv_sec = 1; tv.tv_usec = 0;
        r = select(0, NULL, &wset, NULL, &tv);
        if (r <= 0) { closesocket(s); WSACleanup(); return 0; }
        err = 0; l = (int)sizeof err;
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &l);
        if (err != 0) { closesocket(s); WSACleanup(); return 0; }
    }
    closesocket(s);
    WSACleanup();
    return 1;
}

int main(void)
{
    HMODULE dll;
    version_fn ver; start_fn start; stop_fn stop; running_fn running; config_fn configure;
    const char *v;
    int i;

    printf("AEGIS-Proxy DLL loader\n----------------------\n");
    dll = LoadLibraryA("aegis_proxy.dll");
    if (!dll) {
        printf("Failed to load aegis_proxy.dll (error %lu)\n", GetLastError());
        return 1;
    }
    ver      = (version_fn)GetProcAddress(dll, "aegis_version");
    start    = (start_fn)GetProcAddress(dll, "start_proxy_dll");
    stop     = (stop_fn)GetProcAddress(dll, "stop_proxy_dll");
    running  = (running_fn)GetProcAddress(dll, "is_proxy_running");
    configure = (config_fn)GetProcAddress(dll, "aegis_configure");

    if (!ver || !start || !stop || !running || !configure) {
        printf("DLL missing required exports - refusing to continue.\n");
        FreeLibrary(dll);
        return 1;
    }
    v = ver();
    if (!v || strncmp(v, "AEGIS-Proxy 1.", 14) != 0) {
        printf("Unexpected DLL identity/version: %s\n", v ? v : "(null)");
        FreeLibrary(dll);
        return 1;
    }
    printf("Loaded and validated: %s\n", v);

    if (configure(8181, "127.0.0.1", 100, 1) != 0) {
        printf("aegis_configure rejected parameters.\n");
        FreeLibrary(dll);
        return 1;
    }
    if (!running()) {
        if (start() != 0) {
            printf("start_proxy_dll failed.\n");
            FreeLibrary(dll);
            return 1;
        }
        for (i = 0; i < 40 && !running(); i++) Sleep(50);   /* wait for listener */
        if (!running()) {
            printf("DLL did not reach listening state (bind failure?).\n");
            stop();
            FreeLibrary(dll);
            return 1;
        }
    }
    printf("Smoke test: TCP connect to 127.0.0.1:8181 %s.\n",
           probe_port(8181) ? "SUCCEEDED" : "FAILED");
    printf("Proxy running. Press ENTER to stop and unload...\n");
    getchar();
    stop();
    printf("Stopped. Unloading DLL...\n");
    FreeLibrary(dll);
    printf("Done.\n");
    return 0;
}
