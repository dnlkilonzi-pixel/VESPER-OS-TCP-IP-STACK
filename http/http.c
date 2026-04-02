/*
 * http.c - Minimal HTTP/1.1 client for VESPER OS
 *
 * Implements the single http_get() function declared in include/http.h.
 *
 * Request format (RFC 7230):
 *
 *   GET <path> HTTP/1.1\r\n
 *   Host: <dotted-decimal IP>\r\n
 *   Connection: close\r\n
 *   \r\n
 *
 * "Connection: close" tells the server to send a FIN after the
 * response, which is the signal net_tcp_recv() uses to stop polling.
 */

#include "../include/http.h"
#include "../include/net.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Internal string helpers (no libc available in bare-metal builds)   */
/* ------------------------------------------------------------------ */

/*
 * buf_append_str - copy a NUL-terminated string into buf at pos
 *
 * Returns the updated position (pos + bytes written).
 * Writing stops silently if the buffer is full.
 */
static uint16_t buf_append_str(uint8_t *buf, uint16_t pos, uint16_t cap,
                                const char *s)
{
    while (*s && pos < cap) {
        buf[pos++] = (uint8_t)*s++;
    }
    return pos;
}

/*
 * buf_append_dec - write an unsigned decimal integer into buf at pos
 */
static uint16_t buf_append_dec(uint8_t *buf, uint16_t pos, uint16_t cap,
                                uint32_t v)
{
    char    tmp[11]; /* max 10 decimal digits for UINT32_MAX + NUL */
    int     i = 10;

    tmp[10] = '\0';
    if (v == 0) {
        tmp[--i] = '0';
    } else {
        while (v > 0 && i > 0) {
            tmp[--i] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    return buf_append_str(buf, pos, cap, tmp + i);
}

/*
 * buf_append_ip - write a dotted-decimal IPv4 address into buf
 *
 * @ip : address in host byte order (MSB = first octet)
 */
static uint16_t buf_append_ip(uint8_t *buf, uint16_t pos, uint16_t cap,
                               uint32_t ip)
{
    pos = buf_append_dec(buf, pos, cap, (ip >> 24) & 0xFFU);
    if (pos < cap) buf[pos++] = '.';
    pos = buf_append_dec(buf, pos, cap, (ip >> 16) & 0xFFU);
    if (pos < cap) buf[pos++] = '.';
    pos = buf_append_dec(buf, pos, cap, (ip >>  8) & 0xFFU);
    if (pos < cap) buf[pos++] = '.';
    pos = buf_append_dec(buf, pos, cap,  ip        & 0xFFU);
    return pos;
}

/* ------------------------------------------------------------------ */
/* http_get                                                            */
/* ------------------------------------------------------------------ */

bool http_get(uint32_t    host_ip,
              const char *path,
              uint8_t    *response_buf,
              uint16_t    buf_len,
              uint16_t   *response_len)
{
    tcp_conn_t conn;
    uint8_t    req_buf[256]; /* request is always short */
    uint16_t   req_len = 0;
    uint16_t   rx_len;

    if (!path || !response_buf || buf_len == 0 || !response_len)
        return false;

    *response_len = 0;

    /* --------------------------------------------------------------- */
    /* Step 1: TCP three-way handshake                                 */
    /* --------------------------------------------------------------- */
    klog_puts("[HTTP] Connecting to ");
    klog_ipv4(host_ip);
    klog_puts(":80\r\n");

    if (!net_tcp_connect(&conn, HTTP_LOCAL_PORT, host_ip, HTTP_SERVER_PORT)) {
        klog_puts("[HTTP] TCP connect failed\r\n");
        return false;
    }

    /* --------------------------------------------------------------- */
    /* Step 2: Build the HTTP GET request                              */
    /* --------------------------------------------------------------- */
    req_len = buf_append_str(req_buf, req_len, (uint16_t)sizeof(req_buf),
                             "GET ");
    req_len = buf_append_str(req_buf, req_len, (uint16_t)sizeof(req_buf),
                             path);
    req_len = buf_append_str(req_buf, req_len, (uint16_t)sizeof(req_buf),
                             " HTTP/1.1\r\nHost: ");
    req_len = buf_append_ip (req_buf, req_len, (uint16_t)sizeof(req_buf),
                             host_ip);
    req_len = buf_append_str(req_buf, req_len, (uint16_t)sizeof(req_buf),
                             "\r\nConnection: close\r\n\r\n");

    klog_puts("[HTTP] Sending GET request (");
    klog_udec(req_len);
    klog_puts(" bytes)\r\n");

    if (!net_tcp_send(&conn, req_buf, req_len)) {
        klog_puts("[HTTP] Failed to send request\r\n");
        net_tcp_close(&conn);
        return false;
    }

    /* --------------------------------------------------------------- */
    /* Step 3: Receive the HTTP response                               */
    /* --------------------------------------------------------------- */
    rx_len = net_tcp_recv(&conn, response_buf, buf_len, HTTP_RECV_TIMEOUT);

    klog_puts("[HTTP] Response: ");
    klog_udec(rx_len);
    klog_puts(" bytes\r\n");

    /* --------------------------------------------------------------- */
    /* Step 4: Close the connection                                    */
    /* --------------------------------------------------------------- */
    net_tcp_close(&conn);

    *response_len = rx_len;
    return (rx_len > 0);
}
