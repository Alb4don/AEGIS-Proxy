
#if defined(_WIN32)
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "advapi32.lib")
  #endif
#else
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <sys/time.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <signal.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

#define AEGIS_NAME       "AEGIS-Proxy"
#define AEGIS_VERSION    "1.0.0"
#define AEGIS_FULL_NAME  "AEGIS-Proxy " AEGIS_VERSION

#define DEFAULT_PORT          8181
#define DEFAULT_BIND          "127.0.0.1"
#define DEFAULT_MAX_THREADS   100
#define DEFAULT_IDLE_TIMEOUT  60
#define DEFAULT_CONNECT_TO    10
#define RELAY_BUF_SIZE        16384
#define MAX_HEADER_BYTES      32768
#define MAX_HOST_LEN          253
#define MAX_URL_LEN           2048
#define LISTEN_BACKLOG        128
#define MAX_RULES             64
#define HEADER_READ_TIMEOUT   15
#define SEND_TIMEOUT_S        15

/* ------------------------------------------------------------------ */
/* Build mode: DLL (Windows) or standalone application                 */
/* ------------------------------------------------------------------ */
#if defined(_WIN32) && defined(AEGIS_BUILD_DLL)
  #define AEGIS_EXPORT __declspec(dllexport)
  #define AEGIS_APP_MAIN 0
#else
  #define AEGIS_EXPORT
  #define AEGIS_APP_MAIN 1
#endif


#ifdef _WIN32
typedef volatile LONG     aegis_atomic;
typedef volatile LONGLONG aegis_atomic64;
#define AEGIS_INC(p)     InterlockedIncrement((volatile LONG*)(p))
#define AEGIS_DEC(p)     InterlockedDecrement((volatile LONG*)(p))
#define AEGIS_ADD(p,v)   InterlockedExchangeAdd((volatile LONG*)(p),(LONG)(v))
#define AEGIS_XCHG(p,v)  InterlockedExchange((volatile LONG*)(p),(LONG)(v))
#define AEGIS_ADD64(p,v) InterlockedExchangeAdd64((volatile LONG64*)(p),(LONGLONG)(v))
#else
typedef volatile int      aegis_atomic;
typedef volatile long long aegis_atomic64;
#define AEGIS_INC(p)     __sync_add_and_fetch((p),1)
#define AEGIS_DEC(p)     __sync_sub_and_fetch((p),1)
#define AEGIS_ADD(p,v)   __sync_fetch_and_add((p),(v))
#define AEGIS_XCHG(p,v)  __sync_lock_test_and_set((p),(v))
#define AEGIS_ADD64(p,v) __sync_add_and_fetch((p),(long long)(v))
#endif

#ifdef _WIN32
typedef SOCKET sock_t;
#define AEGIS_INVALID_SOCK INVALID_SOCKET
#else
typedef int sock_t;
#define AEGIS_INVALID_SOCK (-1)
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define AEGIS_SEND_FLAGS MSG_NOSIGNAL


typedef struct {
    int  port;
    char bind_addr[64];
    int  max_threads;
    int  idle_timeout;
    int  connect_timeout;
    int  allow_private;                      
    int  quiet;
    char deny_rules[MAX_RULES][MAX_HOST_LEN + 1];
    int  deny_count;
} aegis_config;

static aegis_config     cfg;
static aegis_atomic     g_running       = 0;
static aegis_atomic     g_active        = 0;
static aegis_atomic     g_stat_conns    = 0;
static aegis_atomic64   g_bytes_up      = 0;
static aegis_atomic64   g_bytes_down    = 0;
static sock_t           g_listen        = AEGIS_INVALID_SOCK;
static volatile sig_atomic_t g_sigint   = 0;

#ifdef _WIN32
static SRWLOCK g_log_lock = SRWLOCK_INIT;    
#else
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

enum { LOG_DEBUG = 0, LOG_INFO = 1, LOG_WARN = 2, LOG_ERROR = 3 };
static int g_log_level = LOG_INFO;
static const char *const g_level_names[] = { "DEBUG", "INFO ", "WARN ", "ERROR" };

static void aegis_localtime(time_t t, struct tm *out)
{
#ifdef _WIN32
    localtime_s(out, &t);
#else
    localtime_r(&t, out);
#endif
}

static void log_msg(int level, const char *fmt, ...)
{
    va_list ap; time_t now; struct tm tmv; char ts[32];
    if (level < g_log_level) return;
    if (level < LOG_DEBUG || level > LOG_ERROR) level = LOG_INFO;
#ifdef _WIN32
    AcquireSRWLockExclusive(&g_log_lock);
#else
    pthread_mutex_lock(&g_log_lock);
#endif
    time(&now);
    aegis_localtime(now, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
    fprintf(stderr, "[%s] [%s] ", ts, g_level_names[level]);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); fflush(stderr);
#ifdef _WIN32
    ReleaseSRWLockExclusive(&g_log_lock);
#else
    pthread_mutex_unlock(&g_log_lock);
#endif
}


static int aegis_strcasecmp(const char *a, const char *b)
{
#ifdef _WIN32
    return _stricmp(a, b);
#else
    return strcasecmp(a, b);
#endif
}

static int aegis_strncasecmp(const char *a, const char *b, size_t n)
{
#ifdef _WIN32
    return _strnicmp(a, b, n);
#else
    return strncasecmp(a, b, n);
#endif
}

static void sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static void sock_close(sock_t s)
{
    if (s == AEGIS_INVALID_SOCK) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}


static void sock_set_timeouts(sock_t s, int recv_sec, int send_sec)
{
#ifdef _WIN32
    DWORD r = (DWORD)recv_sec * 1000, sn = (DWORD)send_sec * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&r, sizeof r);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&sn, sizeof sn);
#else
    struct timeval r, sn;
    r.tv_sec = recv_sec; r.tv_usec = 0;
    sn.tv_sec = send_sec; sn.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &r, sizeof r);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &sn, sizeof sn);
#endif
}

static void sock_tune(sock_t s)
{
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof one);
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof one);
}

static int sock_set_nonblock(sock_t s, int on)
{
#ifdef _WIN32
    u_long mode = on ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(s, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK)) < 0 ? -1 : 0;
#endif
}

static int send_all(sock_t s, const char *buf, int len)
{
    while (len > 0) {
        int n = (int)send(s, buf, len, AEGIS_SEND_FLAGS);
        if (n <= 0) {
#ifndef _WIN32
            if (errno == EINTR) continue;
#endif
            return -1;
        }
        buf += n; len -= n;
    }
    return 0;
}

static const char *aegis_memfind(const char *hay, size_t hlen,
                                 const char *needle, size_t nlen)
{
    size_t i;
    if (nlen == 0) return hay;
    if (hlen < nlen) return NULL;
    for (i = 0; i + nlen <= hlen; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    return NULL;
}

static int is_token_char(unsigned char c)
{
    return isalnum(c) != 0 || strchr("!#$%&'*+-.^_`|~", (char)c) != NULL;
}

static int parse_port(const char *s, int *out)      /* strict 1..65535 */
{
    long v = 0;
    const char *q;
    if (!s || !*s) return 0;
    for (q = s; *q; q++) {
        if (!isdigit((unsigned char)*q)) return 0;
        v = v * 10 + (*q - '0');
        if (v > 65535) return 0;
    }
    if (v < 1) return 0;
    *out = (int)v;
    return 1;
}

static int valid_host_chars(const char *h)
{
    for (; *h; h++) {
        unsigned char c = (unsigned char)*h;
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == ':' || c == '%'))
            return 0;
    }
    return 1;
}


static int ipv4_is_private(uint32_t ip)            
{
    switch (ip >> 24) {
        case 0:   case 10:  case 127: return 1;     
        default: break;
    }
    if ((ip >> 16) == 0xC0A8) return 1;             
    if ((ip >> 20) == 0xAC1)  return 1;            
    if ((ip >> 16) == 0xA9FE) return 1;             
    if ((ip >> 22) == 0x191)  return 1;             
    if ((ip >> 28) >= 0xE)    return 1;            
    return 0;
}

static int addr_is_private(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return ipv4_is_private(ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr));
#ifdef AF_INET6
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)sa;
        if (IN6_IS_ADDR_LOOPBACK(&a6->sin6_addr))    return 1;
        if (IN6_IS_ADDR_LINKLOCAL(&a6->sin6_addr))   return 1;
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {
            uint32_t v4;
            memcpy(&v4, a6->sin6_addr.s6_addr + 12, 4);
            return ipv4_is_private(ntohl(v4));
        }
        if ((a6->sin6_addr.s6_addr[0] & 0xFE) == 0xFC) return 1;  
    }
#endif
    return 0;
}


static int host_matches_rule(const char *host, const char *rule)
{
    if (strncmp(rule, "*.", 2) == 0) {
        const char *suffix = rule + 2;
        size_t hl = strlen(host), sl = strlen(suffix);
        return hl > sl && aegis_strcasecmp(host + hl - sl, suffix) == 0;
    }
    return aegis_strcasecmp(host, rule) == 0;
}

static int policy_denies_host(const char *host)
{
    int i;
    for (i = 0; i < cfg.deny_count; i++) {
        if (host_matches_rule(host, cfg.deny_rules[i])) {
            log_msg(LOG_WARN, "blocked denied host '%s' (matched rule '%s')",
                    host, cfg.deny_rules[i]);
            return 1;
        }
    }
    return 0;
}

static int outbound_addr_filter(const struct sockaddr *sa, void *uctx)
{
    (void)uctx;
    if (!cfg.allow_private && addr_is_private(sa)) {
        char ip[48] = "non-public address";
        if (sa->sa_family == AF_INET) {
            snprintf(ip, sizeof ip, "%s", inet_ntoa(((const struct sockaddr_in *)sa)->sin_addr));
        }
        log_msg(LOG_WARN, "SSRF guard: blocked connection to %s "
                          "(--allow-private overrides)", ip);
        return -1;
    }
    return 0;
}


static int name_is(const char *p, size_t n, const char *name)
{
    size_t l = strlen(name);
    return l == n && aegis_strncasecmp(p, name, n) == 0;
}

static void trim(const char **v, size_t *n)
{
    while (*n && isspace((unsigned char)**v)) { (*v)++; (*n)--; }
    while (*n && isspace((unsigned char)(*v)[*n - 1])) (*n)--;
}

static int find_header_value(const char *head, int head_len, const char *name,
                             char *out, size_t cap)
{
    const char *p = head, *end = head + head_len, *nl, *eol, *colon;
    size_t l, vl;
    nl = memchr(p, '\n', (size_t)(end - p));
    if (!nl) return 0;
    p = nl + 1;
    while (p < end) {
        eol = memchr(p, '\n', (size_t)(end - p));
        l = (eol ? (size_t)(eol - p) : (size_t)(end - p));
        if (l && p[l - 1] == '\r') l--;
        if (l == 0) return 0;
        colon = memchr(p, ':', l);
        if (!colon) return 0;                       
        if (name_is(p, (size_t)(colon - p), name)) {
            const char *v = colon + 1;
            vl = l - (size_t)(colon - p) - 1;
            trim(&v, &vl);
            if (vl == 0 || vl >= cap) return 0;
            memcpy(out, v, vl);
            out[vl] = '\0';
            return 1;
        }
        if (!eol) return 0;
        p = eol + 1;
    }
    return 0;
}


static int parse_authority_str(const char *auth_in, char *host, size_t hcap,
                               int *port, int default_port)
{
    char auth[600];
    char *colon, *rb;
    const char *h;
    if (!auth_in || !*auth_in || strlen(auth_in) >= sizeof auth) return -1;
    strcpy(auth, auth_in);
    *port = default_port;
    if (strchr(auth, '@')) return -1;              
    if (auth[0] == '[') {                          
        rb = strchr(auth, ']');
        if (!rb) return -1;
        *rb = '\0';
        h = auth + 1;
        if (!*h) return -1;
        if (rb[1] == ':') { if (!parse_port(rb + 2, port)) return -1; }
        else if (rb[1] != '\0') return -1;
        if (strlen(h) >= hcap) return -1;
        strcpy(host, h);
    } else {
        colon = strchr(auth, ':');
        if (colon) {
            *colon = '\0';
            if (!parse_port(colon + 1, port)) return -1;
        }
        if (!auth[0] || strlen(auth) >= hcap) return -1;
        strcpy(host, auth);
    }
    return valid_host_chars(host) ? 0 : -1;
}

static int parse_target(const char *target, char *host, size_t hcap, int *port,
                        char *path, size_t pcap)
{
    const char *p = target, *slash, *path_src;
    size_t auth_len;
    char auth[512];
    *port = 80;

    if (!target || !*target) return -1;
    if (target[0] == '*') {                        
        if (target[1] != '\0') return -1;
        snprintf(path, pcap, "*");
        return 1;
    }
    if (target[0] == '/') {
        if (strlen(target) >= pcap) return -1;
        snprintf(path, pcap, "%s", target);
        return 1;
    }
    if (aegis_strncasecmp(target, "http://", 7) == 0) {
        p = target + 7;
    } else if (aegis_strncasecmp(target, "https://", 8) == 0) {
        log_msg(LOG_WARN, "absolute https:// target rejected (plaintext upstream only; "
                          "use CONNECT for TLS)");
        return -1;
    } else if (strstr(target, "://") != NULL) {
        return -1;                                  
    }
    slash = strchr(p, '/');
    auth_len = slash ? (size_t)(slash - p) : strlen(p);
    path_src = slash ? slash : "/";
    if (auth_len == 0 || auth_len >= sizeof auth || strlen(path_src) >= pcap)
        return -1;
    memcpy(auth, p, auth_len);
    auth[auth_len] = '\0';
    if (parse_authority_str(auth, host, hcap, port, 80) != 0) return -1;
    snprintf(path, pcap, "%s", path_src);
    return 0;
}

static int parse_request_line(const char *head, int head_len,
                              char *method, size_t mcap,
                              char *target, size_t tcap,
                              char *version, size_t vcap)
{
    const char *p = head, *end = head + head_len, *sp, *sp2, *eol, *q;
    sp = memchr(p, ' ', (size_t)(end - p));
    if (!sp || sp == p || (size_t)(sp - p) >= mcap) return -1;
    memcpy(method, p, (size_t)(sp - p)); method[sp - p] = '\0';
    p = sp + 1;
    while (p < end && *p == ' ') p++;
    sp2 = memchr(p, ' ', (size_t)(end - p));
    if (!sp2 || sp2 == p || (size_t)(sp2 - p) >= tcap) return -1;
    memcpy(target, p, (size_t)(sp2 - p)); target[sp2 - p] = '\0';
    p = sp2 + 1;
    while (p < end && *p == ' ') p++;
    eol = p;
    while (eol < end && *eol != '\r' && *eol != '\n') eol++;
    if (eol == p || (size_t)(eol - p) >= vcap) return -1;
    memcpy(version, p, (size_t)(eol - p)); version[eol - p] = '\0';
    if (strcmp(version, "HTTP/1.0") != 0 && strcmp(version, "HTTP/1.1") != 0)
        return -1;
    for (q = method; *q; q++)
        if (!is_token_char((unsigned char)*q)) return -1;
    return 0;
}


typedef struct { char *buf; size_t cap; size_t len; } sbuf;

static int sb_append(sbuf *b, const char *src, size_t n)
{
    if (b->len + n >= b->cap) return -1;
    memcpy(b->buf + b->len, src, n);
    b->len += n;
    b->buf[b->len] = '\0';
    return 0;
}

static int sb_puts(sbuf *b, const char *s) { return sb_append(b, s, strlen(s)); }

static int sb_printf(sbuf *b, const char *fmt, ...)
{
    char tmp[1024]; va_list ap; int n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    return sb_append(b, tmp, strlen(tmp));
}


static int build_forward_request(const char *head, int head_len,
                                 const char *method, const char *path,
                                 const char *version, const char *host_header,
                                 const char *client_ip,
                                 char *out, size_t ocap)
{
    sbuf b; int cl = 0, te = 0;
    const char *p, *end, *nl, *eol, *colon;
    size_t l, nlen;
    int drop;

    b.buf = out; b.cap = ocap; b.len = 0; out[0] = '\0';
    if (sb_printf(&b, "%s %s %s\r\n", method, path, version) != 0) return -2;

    p = head; end = head + head_len;
    nl = memchr(p, '\n', (size_t)(end - p));
    if (!nl) return -1;
    p = nl + 1;

    while (p < end) {
        eol = memchr(p, '\n', (size_t)(end - p));
        l = (eol ? (size_t)(eol - p) : (size_t)(end - p));
        if (l && p[l - 1] == '\r') l--;
        if (l == 0) break;                          
        colon = memchr(p, ':', l);
        if (!colon) return -1;                     
        nlen = (size_t)(colon - p);
        drop = 0;
        if (name_is(p, nlen, "host") || name_is(p, nlen, "connection") ||
            name_is(p, nlen, "proxy-connection") || name_is(p, nlen, "keep-alive") ||
            name_is(p, nlen, "proxy-authorization") || name_is(p, nlen, "te") ||
            name_is(p, nlen, "trailer") || name_is(p, nlen, "upgrade")) {
            drop = 1;
        } else if (name_is(p, nlen, "content-length")) {
            cl = 1;
        } else if (name_is(p, nlen, "transfer-encoding")) {
            te = 1;
        }
        if (!drop) {
            if (sb_append(&b, p, l) != 0 || sb_append(&b, "\r\n", 2) != 0) return -2;
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (cl && te) {                                 
        log_msg(LOG_WARN, "rejected request with both Content-Length and "
                          "Transfer-Encoding (smuggling pattern)");
        return -1;
    }
    if (sb_printf(&b, "Host: %s\r\n", host_header) != 0) return -2;
    if (sb_printf(&b, "X-Forwarded-For: %s\r\n", client_ip) != 0) return -2;
    if (sb_puts(&b, "Via: 1.1 aegis-proxy\r\n") != 0) return -2;
    if (sb_puts(&b, "Connection: close\r\n\r\n") != 0) return -2;
    return (int)b.len;
}


typedef int (*addr_filter_fn)(const struct sockaddr *sa, void *uctx);

static sock_t dial_host(const char *host, int port, int timeout_sec,
                        addr_filter_fn flt, void *uctx)
{
    struct addrinfo hints, *res = NULL, *rp;
    char portstr[8];
    sock_t out = AEGIS_INVALID_SOCK;
    int gai;

    snprintf(portstr, sizeof portstr, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;                    
    hints.ai_socktype = SOCK_STREAM;

    gai = getaddrinfo(host, portstr, &hints, &res); 
    if (gai != 0 || !res) {
        log_msg(LOG_WARN, "failed to resolve '%s' (getaddrinfo code %d)", host, gai);
        return AEGIS_INVALID_SOCK;
    }
    for (rp = res; rp; rp = rp->ai_next) {
        sock_t s;
        int rc, r, ok;
        if (flt && flt(rp->ai_addr, uctx) != 0) continue;
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == AEGIS_INVALID_SOCK) continue;
        if (sock_set_nonblock(s, 1) != 0) { sock_close(s); continue; }
        rc = connect(s, rp->ai_addr, (int)rp->ai_addrlen);
        if (rc != 0) {
            fd_set wf;
            struct timeval tv;
#ifdef _WIN32
            fd_set xf;
            if (WSAGetLastError() != WSAEWOULDBLOCK) { sock_close(s); continue; }
            FD_ZERO(&xf); FD_SET(s, &xf);
#endif
            FD_ZERO(&wf); FD_SET(s, &wf);
            tv.tv_sec = timeout_sec; tv.tv_usec = 0;
#ifdef _WIN32
            r = select(0, NULL, &wf, &xf, &tv);
#else
            r = select((int)s + 1, NULL, &wf, NULL, &tv);
#endif
            ok = (r > 0) && FD_ISSET(s, &wf);
            if (ok) {
                int soerr = 0; socklen_t slen = sizeof soerr;
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &slen) != 0 || soerr != 0)
                    ok = 0;
            }
            if (!ok) { sock_close(s); continue; }
        }
        sock_set_nonblock(s, 0);
        out = s;
        break;
    }
    freeaddrinfo(res);
    return out;
}

static void relay_bidirectional(sock_t a, sock_t b, int idle_sec,
                                uint64_t *bytes_a2b, uint64_t *bytes_b2a)
{
    char buf[RELAY_BUF_SIZE];
#ifndef _WIN32
    if (a >= FD_SETSIZE || b >= FD_SETSIZE) {
        log_msg(LOG_ERROR, "fd exceeds FD_SETSIZE - relay aborted");
        return;
    }
#endif
    for (;;) {
        fd_set rf;
        struct timeval tv;
        int r, n;
        FD_ZERO(&rf);
        FD_SET(a, &rf);
        FD_SET(b, &rf);
        tv.tv_sec = idle_sec; tv.tv_usec = 0;
#ifdef _WIN32
        r = select(0, &rf, NULL, NULL, &tv);
#else
        r = select((int)(a > b ? a : b) + 1, &rf, NULL, NULL, &tv);
#endif
        if (r < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) continue;
#else
            if (errno == EINTR) continue;
#endif
            return;
        }
        if (r == 0) { log_msg(LOG_DEBUG, "relay idle timeout (%ds)", idle_sec); return; }
        if (FD_ISSET(a, &rf)) {
            n = (int)recv(a, buf, sizeof buf, 0);
            if (n <= 0) return;
            if (send_all(b, buf, n) != 0) return;
            *bytes_a2b += (uint64_t)n;
        }
        if (FD_ISSET(b, &rf)) {
            n = (int)recv(b, buf, sizeof buf, 0);
            if (n <= 0) return;
            if (send_all(a, buf, n) != 0) return;
            *bytes_b2a += (uint64_t)n;
        }
    }
}


static void send_simple(sock_t s, const char *status_line)
{
    char resp[160];
    int n = snprintf(resp, sizeof resp,
                     "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                     status_line);
    if (n > 0) send_all(s, resp, n);
}

static int method_allowed(const char *m)
{
    static const char *const ok[] = { "GET","HEAD","POST","PUT","DELETE","OPTIONS","PATCH" };
    size_t i;
    for (i = 0; i < sizeof ok / sizeof ok[0]; i++)
        if (aegis_strcasecmp(m, ok[i]) == 0) return 1;
    return 0;                                       
}

static void handle_connect_tunnel(sock_t cs, const char *peer, const char *target)
{
    char host[MAX_HOST_LEN + 1], work[600];
    int port = 443;
    sock_t ss;
    uint64_t up = 0, down = 0;

    if (strchr(target, '/') || strchr(target, ' ') || strlen(target) >= sizeof work) {
        send_simple(cs, "400 Bad Request");
        return;
    }
    strcpy(work, target);
    if (parse_authority_str(work, host, sizeof host, &port, 443) != 0) {
        send_simple(cs, "400 Bad Request");
        return;
    }
    log_msg(LOG_INFO, "CONNECT %s:%d from %s", host, port, peer);
    if (policy_denies_host(host)) { send_simple(cs, "403 Forbidden"); return; }

    ss = dial_host(host, port, cfg.connect_timeout, outbound_addr_filter, NULL);
    if (ss == AEGIS_INVALID_SOCK) { send_simple(cs, "502 Bad Gateway"); return; }

    sock_tune(ss);
    sock_set_timeouts(ss, cfg.idle_timeout, SEND_TIMEOUT_S);

    if (send_all(cs, "HTTP/1.1 200 Connection established\r\n\r\n",
                 (int)strlen("HTTP/1.1 200 Connection established\r\n\r\n")) != 0) {
        sock_close(ss);
        return;
    }
    relay_bidirectional(cs, ss, cfg.idle_timeout, &up, &down);
    AEGIS_ADD64(&g_bytes_up,   (long long)up);
    AEGIS_ADD64(&g_bytes_down, (long long)down);
    log_msg(LOG_INFO, "CONNECT %s:%d from %s closed (up=%llu down=%llu)",
            host, port, peer, (unsigned long long)up, (unsigned long long)down);
    sock_close(ss);
}

static void handle_plain_http(sock_t cs, const char *peer,
                              const char *buf, int total, int head_len,
                              const char *method, const char *target,
                              const char *version)
{
    char host[MAX_HOST_LEN + 1], path[2048], hb[320], canon[MAX_HOST_LEN + 8];
    int port = 80, form, out_len, prefix, rc;
    char *out;
    sock_t ss;
    uint64_t up = 0, down = 0;

    if (!method_allowed(method)) {
        log_msg(LOG_WARN, "%s: rejected method '%s' (not in allowlist)", peer, method);
        send_simple(cs, "405 Method Not Allowed");
        return;
    }
    form = parse_target(target, host, sizeof host, &port, path, sizeof path);
    if (form < 0) { send_simple(cs, "400 Bad Request"); return; }

    if (form == 1) {  /* origin-form: authority must come from Host header */
        if (!find_header_value(buf, head_len, "host", hb, sizeof hb) ||
            parse_authority_str(hb, host, sizeof host, &port, 80) != 0) {
            send_simple(cs, "400 Bad Request");
            return;
        }
    }
    if (port == 80) snprintf(canon, sizeof canon, "%s", host);
    else            snprintf(canon, sizeof canon, "%s:%d", host, port);

    if (policy_denies_host(host)) { send_simple(cs, "403 Forbidden"); return; }

    out = (char *)malloc(MAX_HEADER_BYTES + 1024);
    if (!out) { send_simple(cs, "500 Internal Server Error"); return; }

    out_len = build_forward_request(buf, head_len, method, path, version,
                                    canon, peer, out, MAX_HEADER_BYTES + 1024);
    if (out_len < 0) {
        free(out);
        send_simple(cs, out_len == -2 ? "431 Request Header Fields Too Large"
                                      : "400 Bad Request");
        return;
    }

    ss = dial_host(host, port, cfg.connect_timeout, outbound_addr_filter, NULL);
    if (ss == AEGIS_INVALID_SOCK) { free(out); send_simple(cs, "502 Bad Gateway"); return; }

    sock_tune(ss);
    sock_set_timeouts(ss, cfg.idle_timeout, SEND_TIMEOUT_S);

    rc = send_all(ss, out, out_len);
    prefix = total - head_len;
    if (rc == 0 && prefix > 0) rc = send_all(ss, buf + head_len, prefix);
    free(out);
    if (rc != 0) { sock_close(ss); send_simple(cs, "502 Bad Gateway"); return; }

    relay_bidirectional(cs, ss, cfg.idle_timeout, &up, &down);
    AEGIS_ADD64(&g_bytes_up,   (long long)(up + (uint64_t)out_len + (uint64_t)(prefix > 0 ? prefix : 0)));
    AEGIS_ADD64(&g_bytes_down, (long long)down);
    log_msg(LOG_INFO, "%s %s http://%s:%d%s (up=%llu down=%llu)",
            peer, method, host, port, path,
            (unsigned long long)up, (unsigned long long)down);
    sock_close(ss);
}

static int recv_request_head(sock_t cs, char *buf, int cap,
                             int *total_out, int *head_len_out)
{
    int got = 0;
    sock_set_timeouts(cs, HEADER_READ_TIMEOUT, SEND_TIMEOUT_S);
    while (got < cap - 1) {
        int search_from = (got - 3 > 0) ? got - 3 : 0;
        int n = (int)recv(cs, buf + got, cap - 1 - got, 0);
        const char *term;
        if (n <= 0) return -1;                      
        got += n;
        buf[got] = '\0';
        term = aegis_memfind(buf + search_from, (size_t)(got - search_from), "\r\n\r\n", 4);
        if (term) {
            *head_len_out = (int)(term - buf) + 4;
            *total_out = got;
            return 0;
        }
    }
    log_msg(LOG_WARN, "request headers exceeded %d bytes - rejected (slowloris guard)",
            cap - 1);
    send_simple(cs, "431 Request Header Fields Too Large");
    return -1;
}

static void handle_client(sock_t cs, const char *peer)
{
    char *buf;
    int total = 0, head_len = 0;
    char method[16], target[MAX_URL_LEN + 1], version[16];

    buf = (char *)malloc(MAX_HEADER_BYTES);
    if (!buf) return;
    sock_tune(cs);

    if (recv_request_head(cs, buf, MAX_HEADER_BYTES, &total, &head_len) != 0) {
        free(buf);
        return;
    }
    if (parse_request_line(buf, head_len, method, sizeof method,
                           target, sizeof target, version, sizeof version) != 0) {
        free(buf);
        send_simple(cs, "400 Bad Request");
        return;
    }
    log_msg(LOG_DEBUG, "%s %s %s %s", peer, method, target, version);

    if (aegis_strcasecmp(method, "CONNECT") == 0)
        handle_connect_tunnel(cs, peer, target);
    else
        handle_plain_http(cs, peer, buf, total, head_len, method, target, version);
    free(buf);
}


typedef struct { sock_t sock; char peer[64]; } client_ctx;

#ifdef _WIN32
static DWORD WINAPI client_thread_trampoline(LPVOID arg)
#else
static void *client_thread_trampoline(void *arg)
#endif
{
    client_ctx *ctx = (client_ctx *)arg;
    handle_client(ctx->sock, ctx->peer);
    sock_close(ctx->sock);
    free(ctx);
    AEGIS_DEC(&g_active);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int spawn_client_thread(sock_t cs, const char *peer)
{
    long now;
    client_ctx *ctx;
    now = AEGIS_INC(&g_active);                    
    if ((int)now > cfg.max_threads) {
        AEGIS_DEC(&g_active);
        log_msg(LOG_WARN, "connection limit %d reached - rejecting %s", cfg.max_threads, peer);
        send_simple(cs, "503 Service Unavailable");
        sock_close(cs);
        return -1;
    }
    ctx = (client_ctx *)malloc(sizeof *ctx);
    if (!ctx) {
        AEGIS_DEC(&g_active);
        sock_close(cs);
        log_msg(LOG_ERROR, "out of memory");
        return -1;
    }
    ctx->sock = cs;
    snprintf(ctx->peer, sizeof ctx->peer, "%s", peer);
#ifdef _WIN32
    {
        HANDLE h = CreateThread(NULL, 0, client_thread_trampoline, ctx, 0, NULL);
        if (!h) {
            log_msg(LOG_ERROR, "CreateThread failed (error %lu)", GetLastError());
            AEGIS_DEC(&g_active); sock_close(cs); free(ctx);
            return -1;
        }
        CloseHandle(h);                              /* detached */
    }
#else
    {
        pthread_t tid;
        int rc = pthread_create(&tid, NULL, client_thread_trampoline, ctx);
        if (rc != 0) {
            log_msg(LOG_ERROR, "pthread_create failed (%d)", rc);
            AEGIS_DEC(&g_active); sock_close(cs); free(ctx);
            return -1;
        }
        pthread_detach(tid);
    }
#endif
    AEGIS_ADD(&g_stat_conns, 1);
    return 0;
}


static int init_winsock(void)
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}

static void cleanup_winsock(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static int server_loop(void)
{
    struct sockaddr_in addr;
    sock_t srv;

    if (init_winsock() != 0) { log_msg(LOG_ERROR, "WSAStartup failed"); return -1; }

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == AEGIS_INVALID_SOCK) { log_msg(LOG_ERROR, "socket() failed"); cleanup_winsock(); return -1; }

    {
        int one = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof one);
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(cfg.bind_addr);
    addr.sin_port        = htons((uint16_t)cfg.port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) {
        log_msg(LOG_ERROR, "bind(%s:%d) failed", cfg.bind_addr, cfg.port);
        sock_close(srv); cleanup_winsock(); return -1;
    }
    if (listen(srv, LISTEN_BACKLOG) != 0) {
        log_msg(LOG_ERROR, "listen() failed");
        sock_close(srv); cleanup_winsock(); return -1;
    }
#ifndef _WIN32
    if ((unsigned long)srv >= FD_SETSIZE) {
        log_msg(LOG_ERROR, "listener fd exceeds FD_SETSIZE");
        sock_close(srv); cleanup_winsock(); return -1;
    }
#endif
    g_listen = srv;
    AEGIS_XCHG(&g_running, 1);
    log_msg(LOG_INFO, "listening on %s:%d (max %d clients, idle %ds, private targets %s)",
            cfg.bind_addr, cfg.port, cfg.max_threads, cfg.idle_timeout,
            cfg.allow_private ? "ALLOWED" : "BLOCKED");

    while (g_running) {
#ifndef _WIN32
        if (g_sigint) { log_msg(LOG_INFO, "shutdown: signal received"); AEGIS_XCHG(&g_running, 0); break; }
#endif
        {
            fd_set rf;
            struct timeval tv;
            int r;
            FD_ZERO(&rf);
            FD_SET(srv, &rf);
            tv.tv_sec = 0; tv.tv_usec = 200 * 1000;
#ifdef _WIN32
            r = select(0, &rf, NULL, NULL, &tv);
#else
            r = select((int)srv + 1, &rf, NULL, NULL, &tv);
#endif
            if (r < 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEINTR) continue;
#else
                if (errno == EINTR) continue;
#endif
                log_msg(LOG_ERROR, "select() on listener failed - stopping");
                break;
            }
            if (r == 0) continue;                  

            {
                struct sockaddr_in ca;
                socklen_t clen = sizeof ca;
                sock_t cs = accept(srv, (struct sockaddr *)&ca, &clen);
                if (cs == AEGIS_INVALID_SOCK) {
#ifdef _WIN32
                    int e = WSAGetLastError();
                    if (e == WSAEWOULDBLOCK || e == WSAECONNRESET || e == WSAEINTR) continue;
#else
                    if (errno == EINTR || errno == ECONNABORTED ||
                        errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
                        log_msg(LOG_WARN, "accept: fd/table exhaustion - backing off");
                        sleep_ms(50);
                        continue;
                    }
#endif
                    log_msg(LOG_ERROR, "accept() failed");
                    continue;
                }
                {
                    char peer[64];
                    snprintf(peer, sizeof peer, "%s:%u",
                             inet_ntoa(ca.sin_addr), (unsigned)ntohs(ca.sin_port));
                    log_msg(LOG_DEBUG, "connection from %s", peer);
                    spawn_client_thread(cs, peer);
                }
            }
        }
    }

    sock_close(g_listen);
    g_listen = AEGIS_INVALID_SOCK;

    {   
        int i;
        for (i = 0; i < 100 && g_active > 0; i++) sleep_ms(50);
        if (g_active > 0)
            log_msg(LOG_WARN, "%d client thread(s) still active at shutdown", (int)g_active);
    }
    cleanup_winsock();
    return 0;
}


AEGIS_EXPORT int start_proxy(void)
{
    int rc;
    if (g_running) { log_msg(LOG_WARN, "start_proxy: already running"); return -1; }
    rc = server_loop();
    log_msg(LOG_INFO, "session summary: %ld connections, %llu bytes upstream, %llu bytes downstream",
            (long)g_stat_conns,
            (unsigned long long)g_bytes_up, (unsigned long long)g_bytes_down);
    return rc;
}

AEGIS_EXPORT void stop_proxy(void) { AEGIS_XCHG(&g_running, 0); }

AEGIS_EXPORT int is_proxy_running(void) { return (int)g_running; }

AEGIS_EXPORT const char *aegis_version(void) { return AEGIS_FULL_NAME; }

AEGIS_EXPORT int aegis_configure(int port, const char *bind_addr,
                                 int max_conn, int allow_private)
{
    if (port < 1 || port > 65535) return -1;
    if (!bind_addr || !*bind_addr || strlen(bind_addr) >= sizeof cfg.bind_addr) return -1;
    if (inet_addr(bind_addr) == INADDR_NONE) return -1;
    if (max_conn < 1 || max_conn > 4096) return -1;
    cfg.port = port;
    snprintf(cfg.bind_addr, sizeof cfg.bind_addr, "%s", bind_addr);
    cfg.max_threads = max_conn;
    cfg.allow_private = allow_private;
    return 0;
}

#if defined(_WIN32) && defined(AEGIS_BUILD_DLL)
static SRWLOCK g_dll_lock    = SRWLOCK_INIT;
static HANDLE  g_proxy_thread = NULL;

static DWORD WINAPI proxy_thread_trampoline(LPVOID arg)
{
    (void)arg;
    start_proxy();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID reserved)
{
    (void)mod; (void)reserved;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(mod);
            break;
        case DLL_PROCESS_DETACH:
            AEGIS_XCHG(&g_running, 0);              
            break;
        default:
            break;
    }
    return TRUE;
}

AEGIS_EXPORT int start_proxy_dll(void)
{
    int rc;
    AcquireSRWLockExclusive(&g_dll_lock);
    if (g_running) { ReleaseSRWLockExclusive(&g_dll_lock); return 1; }   
    if (g_proxy_thread) {
        if (WaitForSingleObject(g_proxy_thread, 0) == WAIT_OBJECT_0) {
            CloseHandle(g_proxy_thread);
            g_proxy_thread = NULL;
        } else {
            ReleaseSRWLockExclusive(&g_dll_lock);
            return -1;                             
        }
    }
    g_proxy_thread = CreateThread(NULL, 0, proxy_thread_trampoline, NULL, 0, NULL);
    rc = g_proxy_thread ? 0 : -1;
    ReleaseSRWLockExclusive(&g_dll_lock);
    return rc;
}

AEGIS_EXPORT void stop_proxy_dll(void)
{
    AcquireSRWLockExclusive(&g_dll_lock);
    AEGIS_XCHG(&g_running, 0);
    if (g_proxy_thread) {
        WaitForSingleObject(g_proxy_thread, 5000);
        CloseHandle(g_proxy_thread);
        g_proxy_thread = NULL;
    }
    ReleaseSRWLockExclusive(&g_dll_lock);
}
#endif /* _WIN32 && AEGIS_BUILD_DLL */

#if AEGIS_APP_MAIN

static void banner(void)
{
    printf(
"    _     _____   ____   ___   ____ \n"
"   / \\   | ____| / ___| |_ _| / ___|\n"
"  / _ \\  |  _|  | |  _   | |  \\___ \\\n"
" / ___ \\ | |___ | |_| |  | |   ___) |\n"
"/_/   \\_\\|_____|  \\____| |___| |____/ \n"
"----------------------------------------------------------\n"
"  %s — Hardened HTTP / HTTPS-CONNECT Forward Proxy\n"
"----------------------------------------------------------\n",
        AEGIS_FULL_NAME);
}

static void usage(void)
{
    printf(
"Usage: aegis-proxy [options]\n"
"  -p, --port <n>            listen port (default %d)\n"
"  -b, --bind <addr>         bind address (default %s)\n"
"  -m, --max-conn <n>        max concurrent clients (default %d, max 4096)\n"
"  -t, --idle-timeout <sec>  relay idle timeout (default %d)\n"
"  -i, --connect-timeout <s> upstream connect timeout (default %d)\n"
"      --allow-private       permit upstream private/loopback targets\n"
"      --block-private       deny them (SSRF guard; auto when bound non-loopback)\n"
"      --deny <pattern>      deny host; \"*.dom\" = subdomains (repeatable, max %d)\n"
"  -q, --quiet               warnings/errors only\n"
"  -h, --help\n",
        DEFAULT_PORT, DEFAULT_BIND, DEFAULT_MAX_THREADS,
        DEFAULT_IDLE_TIMEOUT, DEFAULT_CONNECT_TO, MAX_RULES);
}

static int bind_is_loopback(const char *addr)
{
    unsigned long a = inet_addr(addr);
    if (a == INADDR_NONE) return 0;
    return (ntohl(a) >> 24) == 127;
}

#ifdef _WIN32
static int windows_is_elevated(void)   
{
    HANDLE tok = NULL;
    DWORD elev = 0, ret = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    {
        BOOL ok = GetTokenInformation(tok, TokenElevation, &elev, sizeof elev, &ret);
        CloseHandle(tok);
        return ok && elev;
    }
}
static BOOL WINAPI on_console(DWORD ev)
{
    if (ev == CTRL_C_EVENT || ev == CTRL_BREAK_EVENT || ev == CTRL_CLOSE_EVENT) {
        AEGIS_XCHG(&g_running, 0);
        return TRUE;
    }
    return FALSE;
}
#else
static void on_signal(int sig) { (void)sig; g_sigint = 1; }
#endif

static void warn_if_privileged(void)
{
    int loopback = bind_is_loopback(cfg.bind_addr);
    int priv;
#ifdef _WIN32
    priv = windows_is_elevated();
#else
    priv = (geteuid() == 0);
#endif
    if (priv && !loopback)
        log_msg(LOG_WARN, "running ELEVATED while bound to non-loopback %s - "
                          "exposes an unauthenticated proxy to the network", cfg.bind_addr);
    else if (!loopback)
        log_msg(LOG_WARN, "bound to non-loopback %s - open-proxy exposure; "
                          "restrict with firewall rules", cfg.bind_addr);
}

int main(int argc, char **argv)
{
    int i;
    banner();

    memset(&cfg, 0, sizeof cfg);
    cfg.port = DEFAULT_PORT;
    snprintf(cfg.bind_addr, sizeof cfg.bind_addr, "%s", DEFAULT_BIND);
    cfg.max_threads    = DEFAULT_MAX_THREADS;
    cfg.idle_timeout   = DEFAULT_IDLE_TIMEOUT;
    cfg.connect_timeout = DEFAULT_CONNECT_TO;
    cfg.allow_private  = -1;                        /* auto */

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-p") == 0 || strcmp(a, "--port") == 0) {
            if (++i >= argc || !parse_port(argv[i], &cfg.port)) {
                fprintf(stderr, "bad/missing value for %s\n", a); usage(); return 2;
            }
        } else if (strcmp(a, "-b") == 0 || strcmp(a, "--bind") == 0) {
            if (++i >= argc || strlen(argv[i]) >= sizeof cfg.bind_addr) {
                fprintf(stderr, "bad/missing value for %s\n", a); usage(); return 2;
            }
            snprintf(cfg.bind_addr, sizeof cfg.bind_addr, "%s", argv[i]);
        } else if (strcmp(a, "-m") == 0 || strcmp(a, "--max-conn") == 0) {
            int v;
            if (++i >= argc || !parse_port(argv[i], &v) || v > 4096) {
                fprintf(stderr, "bad/missing value for %s\n", a); usage(); return 2;
            }
            cfg.max_threads = v;
        } else if (strcmp(a, "-t") == 0 || strcmp(a, "--idle-timeout") == 0) {
            int v;
            if (++i >= argc || !parse_port(argv[i], &v) || v > 86400) {
                fprintf(stderr, "bad/missing value for %s\n", a); usage(); return 2;
            }
            cfg.idle_timeout = v;
        } else if (strcmp(a, "-i") == 0 || strcmp(a, "--connect-timeout") == 0) {
            int v;
            if (++i >= argc || !parse_port(argv[i], &v) || v > 600) {
                fprintf(stderr, "bad/missing value for %s\n", a); usage(); return 2;
            }
            cfg.connect_timeout = v;
        } else if (strcmp(a, "--allow-private") == 0) {
            cfg.allow_private = 1;
        } else if (strcmp(a, "--block-private") == 0) {
            cfg.allow_private = 0;
        } else if (strcmp(a, "--deny") == 0) {
            if (++i >= argc || cfg.deny_count >= MAX_RULES ||
                strlen(argv[i]) > MAX_HOST_LEN) {
                fprintf(stderr, "bad/missing/excessive --deny rule\n"); usage(); return 2;
            }
            snprintf(cfg.deny_rules[cfg.deny_count], MAX_HOST_LEN + 1, "%s", argv[i]);
            cfg.deny_count++;
        } else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            cfg.quiet = 1;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(); return 0;
        } else {
            fprintf(stderr, "unknown option: %s\n", a); usage(); return 2;
        }
    }

    if (inet_addr(cfg.bind_addr) == INADDR_NONE) {
        fprintf(stderr, "invalid bind address: %s\n", cfg.bind_addr);
        return 2;
    }
    if (cfg.allow_private < 0)
        cfg.allow_private = bind_is_loopback(cfg.bind_addr);  /* auto policy */
    if (cfg.quiet) g_log_level = LOG_WARN;

    log_msg(LOG_INFO, "%s starting (%s build)", AEGIS_FULL_NAME,
#ifdef _WIN32
            "Windows"
#else
            "POSIX"
#endif
    );

#ifdef _WIN32
    SetConsoleCtrlHandler(on_console, TRUE);
#else
    signal(SIGPIPE, SIG_IGN);                      
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#endif

    warn_if_privileged();                           
    return start_proxy() == 0 ? 0 : 1;
}
#endif /* AEGIS_APP_MAIN */
