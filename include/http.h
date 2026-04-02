/*
 * http.h - Minimal HTTP/1.1 client for VESPER OS
 *
 * Provides a single blocking GET request function that:
 *   1. Opens a TCP connection to the server on port 80.
 *   2. Sends a well-formed HTTP/1.1 GET request.
 *   3. Accumulates the response (headers + body) into a caller buffer.
 *   4. Closes the connection after receiving the server's FIN.
 *
 * Usage example:
 *
 *   uint8_t  buf[2048];
 *   uint16_t len = 0;
 *   uint32_t server_ip = ip_make_addr(93, 184, 216, 34); // example.com
 *
 *   if (http_get(server_ip, "/", buf, sizeof(buf), &len)) {
 *       klog_puts("[HTTP] Got response\r\n");
 *   }
 *
 * Limitations (intentional for a minimal bare-metal OS):
 *   - HTTP/1.1 only (no TLS / HTTPS).
 *   - Single-segment receive — multi-segment responses are accumulated
 *     up to @buf_len bytes; excess data is silently dropped.
 *   - No HTTP header parsing beyond storing the raw response bytes.
 *   - No redirect or chunked-transfer handling.
 */

#ifndef VESPER_HTTP_H
#define VESPER_HTTP_H

#include "types.h"
#include "ip.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

/* TCP source port used for outgoing HTTP connections */
#define HTTP_LOCAL_PORT     49200

/* Server TCP port for plain HTTP */
#define HTTP_SERVER_PORT    80

/*
 * Number of net_poll() iterations to wait for the HTTP response.
 * At ~1 µs per poll iteration this is roughly 2 seconds.
 */
#define HTTP_RECV_TIMEOUT   2000000U

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * http_get - Perform a blocking HTTP/1.1 GET request
 *
 * Connects to @host_ip:80, sends "GET <path> HTTP/1.1", and reads the
 * full response (headers + body) into @response_buf.
 *
 * The response is NOT NUL-terminated automatically; callers should
 * ensure they leave one extra byte in @buf_len and NUL-terminate if
 * they intend to use string functions on the result.
 *
 * @host_ip      : IPv4 address of the HTTP server (host byte order)
 * @path         : URL path to request (e.g. "/" or "/index.html")
 * @response_buf : caller-allocated buffer for the raw HTTP response
 * @buf_len      : size of @response_buf in bytes
 * @response_len : output — set to the number of bytes written into
 *                 @response_buf (may be 0 on failure)
 *
 * Returns true if the connection and request succeeded and at least
 * one byte of response was received, false on any error.
 */
bool http_get(uint32_t host_ip,
              const char *path,
              uint8_t    *response_buf,
              uint16_t    buf_len,
              uint16_t   *response_len);

#endif /* VESPER_HTTP_H */
