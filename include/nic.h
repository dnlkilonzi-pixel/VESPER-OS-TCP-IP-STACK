/*
 * nic.h - Network Interface Card driver abstraction for VESPER OS
 *
 * Provides a thin hardware-abstraction layer over the NIC so that the
 * upper network layers (Ethernet / IP / TCP) never touch hardware
 * registers directly.
 *
 * Initially this is a stub implementation that either:
 *   (a) talks to a QEMU e1000 or RTL8139 emulated card via MMIO/PIO, or
 *   (b) records transmitted frames in a ring buffer for unit testing.
 *
 * Only one NIC instance is supported (the system's primary interface).
 */

#ifndef VESPER_NIC_H
#define VESPER_NIC_H

#include "types.h"
#include "ethernet.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define NIC_TX_RING_SIZE  16    /* Number of transmit descriptor slots  */
#define NIC_RX_RING_SIZE  16    /* Number of receive descriptor slots   */
#define NIC_MAX_PKT_SIZE  1518  /* Max Ethernet frame size (w/o FCS)   */

/* ------------------------------------------------------------------ */
/* NIC receive callback type                                           */
/* ------------------------------------------------------------------ */

/*
 * nic_rx_handler_t - Callback invoked when a frame is received
 *
 * @frame   : pointer to the received raw Ethernet frame data
 * @length  : byte count of the frame (header + payload)
 */
typedef void (*nic_rx_handler_t)(const uint8_t *frame, uint16_t length);

/* ------------------------------------------------------------------ */
/* NIC driver structure                                                */
/* ------------------------------------------------------------------ */

/*
 * nic_driver_t - Abstract NIC driver interface
 *
 * Every NIC driver fills in these function pointers.  Upper layers call
 * through this interface so they are decoupled from hardware specifics.
 */
typedef struct {
    /* Human-readable driver name (for logging) */
    const char *name;

    /* NIC hardware MAC address (6 bytes) — set during init */
    uint8_t mac[ETH_ALEN];

    /* Whether the driver is ready to send/receive */
    bool    ready;

    /*
     * init - Detect and initialise the NIC hardware
     *
     * Returns true on success, false if the hardware was not found.
     */
    bool (*init)(void);

    /*
     * send - Transmit a raw Ethernet frame
     *
     * @frame : pointer to the frame bytes (starting with the Ethernet header)
     * @length: byte count of the complete frame
     *
     * Returns true if the frame was accepted by the hardware, false on error.
     */
    bool (*send)(const uint8_t *frame, uint16_t length);

    /*
     * poll - Check for received frames and invoke the registered handler
     *
     * Should be called periodically from the kernel main loop or an IRQ
     * handler.  For each complete frame received, the registered rx_handler
     * is called.
     */
    void (*poll)(void);

    /*
     * register_rx_handler - Register a callback for incoming frames
     *
     * @handler : callback function (or NULL to deregister)
     */
    void (*register_rx_handler)(nic_rx_handler_t handler);
} nic_driver_t;

/* ------------------------------------------------------------------ */
/* Stub / loopback driver (always available for testing)               */
/* ------------------------------------------------------------------ */

/*
 * nic_stub_driver - A software loopback NIC that stores sent frames in
 *                   an internal ring buffer.
 *
 * Useful for unit testing packet construction without real hardware.
 * Sent frames are also echoed back to the rx_handler so upper layers
 * can observe what they transmitted.
 */
extern nic_driver_t nic_stub_driver;

/* ------------------------------------------------------------------ */
/* Global NIC handle                                                   */
/* ------------------------------------------------------------------ */

/*
 * g_nic - Pointer to the active NIC driver
 *
 * Set by nic_init() to either the real hardware driver or the stub
 * (if no hardware is detected).
 */
extern nic_driver_t *g_nic;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * nic_init - Detect hardware and initialise the NIC driver
 *
 * Sets g_nic to the detected driver (or stub if nothing is found).
 * Must be called before any send/receive operations.
 *
 * Returns true if a real NIC was found, false if the stub was used.
 */
bool nic_init(void);

/*
 * nic_send_frame - Transmit an Ethernet frame through the active NIC
 *
 * Convenience wrapper around g_nic->send().
 *
 * @frame  : pointer to the raw Ethernet frame (from eth_frame_t)
 * @length : byte count of the frame
 *
 * Returns true on success.
 */
bool nic_send_frame(const uint8_t *frame, uint16_t length);

/*
 * nic_poll - Poll the active NIC for received frames
 *
 * Wrapper around g_nic->poll().  Call this from the main network loop
 * or inside a timer interrupt handler.
 */
void nic_poll(void);

/*
 * nic_register_rx_handler - Register a frame receive callback
 *
 * @handler : function to call for each received frame
 */
void nic_register_rx_handler(nic_rx_handler_t handler);

/*
 * nic_get_mac - Copy the NIC's MAC address into @mac_out (6 bytes)
 */
void nic_get_mac(uint8_t *mac_out);

#endif /* VESPER_NIC_H */
