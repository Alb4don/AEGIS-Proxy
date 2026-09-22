### `Building`

      | Linux / macOS | gcc -O2 -Wall -Wextra -pthread aegis_proxy.c -o aegis-proxy |
      | Windows EXE (MSVC) | cl /O2 /W4 aegis_proxy.c /Fe:aegis-proxy.exe /link ws2_32.lib advapi32.lib |
      | Windows DLL (MSVC) | cl /LD /O2 /W4 /DAEGIS_BUILD_DLL aegis_proxy.c /Fe:aegis_proxy.dll |
      | Windows EXE (MinGW) | gcc -O2 -Wall -Wextra aegis_proxy.c -o aegis-proxy.exe -lws2_32 -ladvapi32 |
      | Windows DLL (MinGW) | gcc -O2 -Wall -Wextra -DAEGIS_BUILD_DLL -shared aegis_proxy.c -o aegis_proxy.dll -lws2_32 -ladvapi32 |
      | DLL loader | gcc -O2 -Wall aegis_loader.c -o aegis_loader.exe -lws2_32 |

- advapi32 is linked for the token-elevation check in the standalone Windows build. There are no third-party libraries.

### `Usage`

      aegis-proxy

- That listens on ***127.0.0.1:8181***, permits private upstream targets (loopback bind), and logs INFO and above to stderr.

        | Option | Default | Description |
        | -p, --port | 8181 | Listen port |
        | -b, --bind | 127.0.0.1 | Bind address |
        | -m, --max-conn | 100 | Concurrent client cap, hard max 4096 |
        | -t, --idle-timeout | 60 | Relay idle timeout, seconds, max 86400 |
        | -i, --connect-timeout | 10 | Upstream connect timeout, seconds, max 600 |
        | --allow-private / --block-private` | auto | Private target policy; auto resolves from bind address |
        | --deny PATTERN | none | Deny host or .domain, repeatable, 64 max |
        | -q, --quiet | off | Warnings and errors only |


- When bound to a non-loopback address the proxy warns that it is running as an open proxy and restricts with firewall rules.
- If the process is elevated (root on POSIX, TokenElevation on Windows) while bound non-loopback, it says so too.

### `Checking it works`

        curl -x http://127.0.0.1:8181 http://test.com/
        curl -x http://127.0.0.1:8181 https://test.com/
        curl -x http://127.0.0.1:8181 --block-private http://169.254.169.254/latest/meta-data/
        aegis-proxy --deny .internal.corp

- The third command returns 502 and the log names the blocked address under the SSRF guard.
- With the deny rule active, a request to any .internal.corp host returns 403 before a single DNS lookup happens.
