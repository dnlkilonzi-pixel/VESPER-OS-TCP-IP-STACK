/*
 * main.c - VESPER OS TCP/IP stack demonstration entry point
 *
 * This file shows how the kernel would invoke the network stack to:
 *   1. Initialise the network subsystem
 *   2. Perform a TCP three-way handshake with a remote host
 *   3. Send a data payload ("Hello from VESPER")
 *   4. Gracefully close the connection
 *
 * In a real VESPER OS kernel this would be called from the kernel main
 * function after memory management and interrupt handling are set up.
 * Here it is structured as a standalone demonstration.
 *
 * Network configuration used in this demo:
 *   Local  IP:  192.168.1.10
 *   Remote IP:  192.168.1.1  (acts as server on port 8080)
 *   Gateway:    192.168.1.1
 */

#include "include/net.h"
#include "include/types.h"
#include "include/klog.h"

/* ------------------------------------------------------------------ */
/* Hard-coded network configuration                                    */
/* ------------------------------------------------------------------ */

/* Local IP: 192.168.1.10 */
#define LOCAL_IP    ip_make_addr(192, 168, 1, 10)

/* Remote / gateway IP: 192.168.1.1 */
#define REMOTE_IP   ip_make_addr(192, 168, 1, 1)

/* Source TCP port */
#define LOCAL_PORT  49152

/* Destination TCP port (e.g. a simple echo server) */
#define REMOTE_PORT 8080

/* Gateway MAC (static ARP — replace with real gateway MAC in production) */
static const uint8_t GATEWAY_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02};

/* Message to send after the handshake */
static const uint8_t MSG[] = "Hello from VESPER";

/* ------------------------------------------------------------------ */
/* vesper_net_demo - run the full TCP/IP demonstration                 */
/* ------------------------------------------------------------------ */

void vesper_net_demo(void)
{
    net_config_t config;
    tcp_conn_t   conn;
    bool         ok;

    klog_puts("========================================\r\n");
    klog_puts("  VESPER OS TCP/IP Stack Demo\r\n");
    klog_puts("========================================\r\n");

    /* --------------------------------------------------------------- */
    /* Step 1: Configure and initialise the network subsystem          */
    /* --------------------------------------------------------------- */
    config.local_ip   = LOCAL_IP;
    config.gateway_ip = REMOTE_IP;
    config.netmask    = ip_make_addr(255, 255, 255, 0);

    /* gateway_mac must be set before net_init(); local_mac is filled by NIC */
    {
        int i;
        for (i = 0; i < 6; i++)
            config.gateway_mac[i] = GATEWAY_MAC[i];
    }

    net_init(&config);

    /* --------------------------------------------------------------- */
    /* Step 2: Perform the TCP three-way handshake                     */
    /* --------------------------------------------------------------- */
    klog_puts("[DEMO] Starting TCP connect to ");
    klog_ipv4(REMOTE_IP);
    klog_puts(":");
    klog_udec(REMOTE_PORT);
    klog_puts("\r\n");

    ok = net_tcp_connect(&conn, LOCAL_PORT, REMOTE_IP, REMOTE_PORT);

    if (!ok) {
        klog_puts("[DEMO] TCP connect failed\r\n");
        return;
    }

    /* --------------------------------------------------------------- */
    /* Step 3: Send data payload                                        */
    /* --------------------------------------------------------------- */
    klog_puts("[DEMO] Sending payload: \"");
    klog_puts((const char *)MSG);
    klog_puts("\"\r\n");

    ok = net_tcp_send(&conn, MSG, (uint16_t)(sizeof(MSG) - 1));

    if (!ok) {
        klog_puts("[DEMO] Data send failed\r\n");
    } else {
        klog_puts("[DEMO] Payload sent successfully\r\n");
    }

    /* --------------------------------------------------------------- */
    /* Step 4: Close the connection gracefully                          */
    /* --------------------------------------------------------------- */
    net_tcp_close(&conn);

    klog_puts("[DEMO] Connection closed\r\n");
    klog_puts("========================================\r\n");
}

/* ------------------------------------------------------------------ */
/* Kernel entry point                                                  */
/* ------------------------------------------------------------------ */

/*
 * kernel_main - Called by the bootloader after entering protected mode
 *
 * In a full VESPER OS this would initialise memory, interrupts and
 * other subsystems first.  For the network stack demo we jump straight
 * to the networking code.
 */
void kernel_main(void)
{
    /* Set log level to DEBUG so all network tracing is visible */
    klog_level = KLOG_DEBUG;

    vesper_net_demo();

    /* Halt the CPU */
    for (;;)
        __asm__ volatile ("hlt");
}
