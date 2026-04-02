/*
 * e1000.c - Intel 8254x (e1000) NIC driver for VESPER OS
 *
 * Implements a minimal driver for the Intel 82540EM Gigabit Ethernet
 * controller, which is the NIC emulated by QEMU when you pass:
 *
 *   -netdev user,id=n0 -device e1000,netdev=n0
 *
 * The driver performs:
 *   1. PCI config-space scan (bus 0, devices 0-31) to find vendor
 *      0x8086 / device 0x100E.
 *   2. BAR0 read to obtain the MMIO base address.
 *   3. Device reset and link-up via the CTRL register.
 *   4. MAC address read from RAL0/RAH0 (set by QEMU from the
 *      -device e1000,mac=... option, or a default).
 *   5. TX descriptor ring setup (E1000_NUM_TX_DESC descriptors).
 *   6. RX descriptor ring setup (E1000_NUM_RX_DESC descriptors).
 *   7. send() — copies the frame into the next TX buffer, writes
 *      the descriptor, bumps TDT, and waits for DD.
 *   8. poll() — scans the RX ring for completed descriptors and
 *      delivers each frame to the registered rx_handler.
 *
 * In TEST_HOST builds (native gcc with -DTEST_HOST) all hardware
 * access is omitted and init() immediately returns false so the
 * stub NIC is used instead.
 *
 * Memory layout note:
 *   The descriptor rings and packet buffers are declared as static
 *   arrays.  For QEMU with identity-mapped physical memory these
 *   virtual addresses equal their physical addresses, which is what
 *   the e1000 DMA engine requires.
 */

#include "../include/e1000.h"
#include "../include/nic.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Static state (bare-metal only)                                      */
/* ------------------------------------------------------------------ */

#ifndef TEST_HOST

/* MMIO base pointer — set during init from BAR0 */
static volatile uint32_t *e1000_mmio = NULL;

/* Descriptor rings — must be 16-byte aligned */
static e1000_tx_desc_t tx_descs[E1000_NUM_TX_DESC]
    __attribute__((aligned(16)));
static e1000_rx_desc_t rx_descs[E1000_NUM_RX_DESC]
    __attribute__((aligned(16)));

/* Packet buffers behind each descriptor */
static uint8_t tx_bufs[E1000_NUM_TX_DESC][NIC_MAX_PKT_SIZE];
static uint8_t rx_bufs[E1000_NUM_RX_DESC][NIC_MAX_PKT_SIZE];

/* Current tail indices */
static uint8_t g_tx_tail = 0;
static uint8_t g_rx_tail = 0;

/* Registered receive handler */
static nic_rx_handler_t g_rx_handler = NULL;

/* ------------------------------------------------------------------ */
/* MMIO register accessors                                             */
/* ------------------------------------------------------------------ */

static uint32_t e1000_read(uint32_t offset)
{
    return e1000_mmio[offset >> 2];
}

static void e1000_write(uint32_t offset, uint32_t val)
{
    e1000_mmio[offset >> 2] = val;
}

/* ------------------------------------------------------------------ */
/* PCI config space access (x86 I/O port method)                      */
/* ------------------------------------------------------------------ */

/*
 * PCI configuration mechanism #1:
 *   Write the address to port 0xCF8, read/write data from port 0xCFC.
 *
 * CONFIG_ADDRESS format (32 bits):
 *   [31]    = enable bit (1)
 *   [23:16] = bus number
 *   [15:11] = device number
 *   [10:8]  = function number
 *   [7:2]   = register number (DWORD index)
 *   [1:0]   = 0 (byte select handled by port offset)
 */
#define PCI_CONFIG_ADDR_PORT  0xCF8U
#define PCI_CONFIG_DATA_PORT  0xCFCU

static inline void outl(uint16_t port, uint32_t val)
{
    __asm__ volatile ("outl %0, %w1" : : "a"(val), "Nd"(port));
}

static inline uint32_t inl(uint16_t port)
{
    uint32_t ret;
    __asm__ volatile ("inl %w1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static uint32_t pci_config_read(uint8_t bus, uint8_t dev,
                                uint8_t func, uint8_t reg)
{
    uint32_t addr = (1U << 31)          |
                    ((uint32_t)bus  << 16) |
                    ((uint32_t)dev  << 11) |
                    ((uint32_t)func <<  8) |
                    ((uint32_t)(reg & 0xFC));
    outl((uint16_t)PCI_CONFIG_ADDR_PORT, addr);
    return inl((uint16_t)PCI_CONFIG_DATA_PORT);
}

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void mem_copy(void *dst, const void *src, size_t len)
{
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    size_t i;
    for (i = 0; i < len; i++)
        d[i] = s[i];
}

static void mem_zero(void *dst, size_t len)
{
    uint8_t *d = (uint8_t *)dst;
    size_t i;
    for (i = 0; i < len; i++)
        d[i] = 0;
}

/* Busy-wait for a condition — limit iterations to avoid infinite loops */
#define E1000_SPIN_LIMIT  1000000U

/* ------------------------------------------------------------------ */
/* e1000_init                                                          */
/* ------------------------------------------------------------------ */

static bool e1000_init(void)
{
    uint8_t  bus, dev;
    uint32_t id;
    uint32_t bar0;
    uint32_t ral, rah;
    uint8_t  mac[ETH_ALEN];
    uint32_t i;
    uint32_t spin;

    /* --- Step 1: Scan PCI bus 0 for the e1000 --- */
    for (bus = 0; bus < 8; bus++) {
        for (dev = 0; dev < 32; dev++) {
            id = pci_config_read(bus, dev, 0, 0x00);
            if ((id & 0xFFFF) == E1000_VENDOR_ID &&
                ((id >> 16) & 0xFFFF) == E1000_DEVICE_ID) {
                goto found;
            }
        }
    }
    klog_puts("[E1000] Device not found on PCI bus\r\n");
    return false;

found:
    klog_puts("[E1000] Found at PCI bus=");
    klog_udec(bus);
    klog_puts(" dev=");
    klog_udec(dev);
    klog_puts("\r\n");

    /* --- Step 2: Read BAR0 (MMIO base address) --- */
    bar0 = pci_config_read(bus, dev, 0, 0x10);
    if (bar0 & 0x1) {
        /* I/O space BAR — unexpected for e1000 */
        klog_puts("[E1000] BAR0 is I/O space, expected MMIO\r\n");
        return false;
    }
    /* Mask the lower attribute bits to get the base address */
    e1000_mmio = (volatile uint32_t *)(uintptr_t)(bar0 & ~0x0FU);
    klog_puts("[E1000] MMIO base=0x");
    klog_hex32((uint32_t)(uintptr_t)e1000_mmio);
    klog_puts("\r\n");

    /* --- Step 3: Reset the device --- */
    e1000_write(E1000_REG_CTRL,
                e1000_read(E1000_REG_CTRL) | E1000_CTRL_RST);
    /* Wait for reset to complete (RST self-clears) */
    for (spin = 0; spin < E1000_SPIN_LIMIT; spin++) {
        if (!(e1000_read(E1000_REG_CTRL) & E1000_CTRL_RST))
            break;
    }

    /* --- Step 4: Set link up --- */
    e1000_write(E1000_REG_CTRL,
                e1000_read(E1000_REG_CTRL) | E1000_CTRL_SLU);

    /* --- Step 5: Read MAC address from RAL0/RAH0 --- */
    ral = e1000_read(E1000_REG_RAL0);
    rah = e1000_read(E1000_REG_RAH0);
    mac[0] = (uint8_t)(ral);
    mac[1] = (uint8_t)(ral >>  8);
    mac[2] = (uint8_t)(ral >> 16);
    mac[3] = (uint8_t)(ral >> 24);
    mac[4] = (uint8_t)(rah);
    mac[5] = (uint8_t)(rah >>  8);

    for (i = 0; i < ETH_ALEN; i++)
        e1000_driver.mac[i] = mac[i];

    klog_puts("[E1000] MAC: ");
    klog_mac(e1000_driver.mac);
    klog_puts("\r\n");

    /* --- Step 6: Set up TX descriptor ring --- */
    mem_zero(tx_descs, sizeof(tx_descs));
    for (i = 0; i < E1000_NUM_TX_DESC; i++) {
        tx_descs[i].addr   = (uint64_t)(uintptr_t)tx_bufs[i];
        tx_descs[i].status = E1000_TXD_STAT_DD; /* mark as done initially */
    }
    g_tx_tail = 0;

    e1000_write(E1000_REG_TDBAL, (uint32_t)(uintptr_t)tx_descs);
    e1000_write(E1000_REG_TDBAH, 0);
    e1000_write(E1000_REG_TDLEN,
                (uint32_t)(E1000_NUM_TX_DESC * sizeof(e1000_tx_desc_t)));
    e1000_write(E1000_REG_TDH, 0);
    e1000_write(E1000_REG_TDT, 0);
    e1000_write(E1000_REG_TCTL,
                E1000_TCTL_EN | E1000_TCTL_PSP |
                E1000_TCTL_CT_DEF | E1000_TCTL_COLD_DEF);
    /* Standard inter-packet gap (from the SDM) */
    e1000_write(E1000_REG_TIPG, 0x0060200AU);

    /* --- Step 7: Set up RX descriptor ring --- */
    mem_zero(rx_descs, sizeof(rx_descs));
    for (i = 0; i < E1000_NUM_RX_DESC; i++) {
        rx_descs[i].addr   = (uint64_t)(uintptr_t)rx_bufs[i];
        rx_descs[i].status = 0;
    }
    g_rx_tail = E1000_NUM_RX_DESC - 1;

    e1000_write(E1000_REG_RDBAL, (uint32_t)(uintptr_t)rx_descs);
    e1000_write(E1000_REG_RDBAH, 0);
    e1000_write(E1000_REG_RDLEN,
                (uint32_t)(E1000_NUM_RX_DESC * sizeof(e1000_rx_desc_t)));
    e1000_write(E1000_REG_RDH, 0);
    e1000_write(E1000_REG_RDT, g_rx_tail);
    e1000_write(E1000_REG_RCTL,
                E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_BSIZE_2K);

    klog_puts("[E1000] Initialised — TX/RX rings active\r\n");
    return true;
}

/* ------------------------------------------------------------------ */
/* e1000_send                                                          */
/* ------------------------------------------------------------------ */

static bool e1000_send(const uint8_t *frame, uint16_t length)
{
    uint32_t spin;
    uint8_t  slot;

    if (!frame || length == 0 || length > NIC_MAX_PKT_SIZE)
        return false;
    if (!e1000_mmio) return false;

    slot = g_tx_tail;

    /* Wait for the current slot's DD bit (hardware done with it) */
    for (spin = 0; spin < E1000_SPIN_LIMIT; spin++) {
        if (tx_descs[slot].status & E1000_TXD_STAT_DD)
            break;
    }
    if (!(tx_descs[slot].status & E1000_TXD_STAT_DD)) {
        klog_puts("[E1000] TX ring full — dropping frame\r\n");
        return false;
    }

    /* Copy the frame into the TX buffer */
    mem_copy(tx_bufs[slot], frame, length);

    /* Fill the descriptor */
    tx_descs[slot].length = length;
    tx_descs[slot].cso    = 0;
    tx_descs[slot].cmd    = E1000_TXD_CMD_EOP |
                            E1000_TXD_CMD_IFCS |
                            E1000_TXD_CMD_RS;
    tx_descs[slot].status = 0; /* clear DD so hardware can use it */
    tx_descs[slot].css    = 0;
    tx_descs[slot].special = 0;

    /* Advance tail — this kicks the hardware */
    g_tx_tail = (uint8_t)((g_tx_tail + 1) % E1000_NUM_TX_DESC);
    e1000_write(E1000_REG_TDT, g_tx_tail);

    klog_puts("[E1000] TX ");
    klog_udec(length);
    klog_puts(" bytes\r\n");
    return true;
}

/* ------------------------------------------------------------------ */
/* e1000_poll                                                          */
/* ------------------------------------------------------------------ */

static void e1000_poll(void)
{
    uint8_t next;

    if (!e1000_mmio) return;

    /*
     * Walk the RX ring from g_rx_tail+1 (the next descriptor the
     * hardware will fill) and deliver any completed frames.
     */
    for (;;) {
        next = (uint8_t)((g_rx_tail + 1) % E1000_NUM_RX_DESC);

        /* Check if the hardware has written a frame into this slot */
        if (!(rx_descs[next].status & E1000_RXD_STAT_DD))
            break; /* no more frames ready */

        if (rx_descs[next].length > 0 && g_rx_handler) {
            g_rx_handler(rx_bufs[next], rx_descs[next].length);
        }

        /* Return the descriptor to the hardware */
        rx_descs[next].status = 0;
        g_rx_tail = next;
        e1000_write(E1000_REG_RDT, g_rx_tail);
    }
}

/* ------------------------------------------------------------------ */
/* e1000_register_rx_handler                                          */
/* ------------------------------------------------------------------ */

static void e1000_register_rx_handler(nic_rx_handler_t handler)
{
    g_rx_handler = handler;
}

#else /* TEST_HOST — no hardware access */

static bool e1000_init(void)              { return false; }
static bool e1000_send(const uint8_t *f,
                       uint16_t l)        { (void)f; (void)l; return false; }
static void e1000_poll(void)              {}
static void e1000_register_rx_handler(nic_rx_handler_t h) { (void)h; }

#endif /* TEST_HOST */

/* ------------------------------------------------------------------ */
/* Public driver instance                                              */
/* ------------------------------------------------------------------ */

nic_driver_t e1000_driver = {
    .name                = "e1000",
    .ready               = false,
    .init                = e1000_init,
    .send                = e1000_send,
    .poll                = e1000_poll,
    .register_rx_handler = e1000_register_rx_handler,
};
