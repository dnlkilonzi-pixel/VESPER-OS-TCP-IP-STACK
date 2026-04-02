/*
 * e1000.h - Intel 8254x (e1000) NIC driver definitions for VESPER OS
 *
 * Covers the register map and descriptor layout for the Intel 82540EM
 * (QEMU default e1000 emulation, PCI vendor 0x8086 / device 0x100E).
 *
 * Reference: Intel 8254x Family of Gigabit Ethernet Controllers
 *            Software Developer's Manual, Revision 4.0.
 *
 * Hardware access note:
 *   All register reads/writes go through MMIO (BAR0).  PCI I/O space
 *   access (ports 0xCF8/0xCFC) is used only during initialisation to
 *   locate the device and read BAR0.  Both are guarded with
 *   #ifndef TEST_HOST so they are omitted from native unit-test builds.
 */

#ifndef VESPER_E1000_H
#define VESPER_E1000_H

#include "types.h"
#include "nic.h"

/* ------------------------------------------------------------------ */
/* PCI identifiers                                                     */
/* ------------------------------------------------------------------ */

#define E1000_VENDOR_ID     0x8086U  /* Intel Corporation            */
#define E1000_DEVICE_ID     0x100EU  /* 82540EM (QEMU default)       */

/* ------------------------------------------------------------------ */
/* MMIO register offsets (byte offsets from BAR0 base)                */
/* ------------------------------------------------------------------ */

#define E1000_REG_CTRL      0x00000U  /* Device Control               */
#define E1000_REG_STATUS    0x00008U  /* Device Status                 */
#define E1000_REG_RCTL      0x00100U  /* Receive Control               */
#define E1000_REG_TCTL      0x00400U  /* Transmit Control              */
#define E1000_REG_TIPG      0x00410U  /* TX Inter-Packet Gap           */
#define E1000_REG_RDBAL     0x02800U  /* RX Descriptor Base Addr Low   */
#define E1000_REG_RDBAH     0x02804U  /* RX Descriptor Base Addr High  */
#define E1000_REG_RDLEN     0x02808U  /* RX Descriptor Ring Length     */
#define E1000_REG_RDH       0x02810U  /* RX Descriptor Head            */
#define E1000_REG_RDT       0x02818U  /* RX Descriptor Tail            */
#define E1000_REG_TDBAL     0x03800U  /* TX Descriptor Base Addr Low   */
#define E1000_REG_TDBAH     0x03804U  /* TX Descriptor Base Addr High  */
#define E1000_REG_TDLEN     0x03808U  /* TX Descriptor Ring Length     */
#define E1000_REG_TDH       0x03810U  /* TX Descriptor Head            */
#define E1000_REG_TDT       0x03818U  /* TX Descriptor Tail            */
#define E1000_REG_RAL0      0x05400U  /* Receive Address Low  (slot 0) */
#define E1000_REG_RAH0      0x05404U  /* Receive Address High (slot 0) */

/* ------------------------------------------------------------------ */
/* CTRL register bits                                                  */
/* ------------------------------------------------------------------ */

#define E1000_CTRL_SLU      (1U << 6)   /* Set Link Up                */
#define E1000_CTRL_RST      (1U << 26)  /* Device Reset               */

/* ------------------------------------------------------------------ */
/* RCTL register bits                                                  */
/* ------------------------------------------------------------------ */

#define E1000_RCTL_EN       (1U << 1)   /* Receiver Enable            */
#define E1000_RCTL_BAM      (1U << 15)  /* Broadcast Accept Mode      */
#define E1000_RCTL_BSIZE_2K 0x00000000U /* Buffer size 2048 bytes     */

/* ------------------------------------------------------------------ */
/* TCTL register bits                                                  */
/* ------------------------------------------------------------------ */

#define E1000_TCTL_EN       (1U << 1)   /* Transmit Enable            */
#define E1000_TCTL_PSP      (1U << 3)   /* Pad Short Packets          */
/* Collision threshold (CT) = 0x0F, stored at bits 11:4 */
#define E1000_TCTL_CT_DEF   (0x0FU << 4)
/* Collision distance (COLD) = 0x040 for full-duplex, bits 21:12 */
#define E1000_TCTL_COLD_DEF (0x040U << 12)

/* ------------------------------------------------------------------ */
/* RAH register bits                                                   */
/* ------------------------------------------------------------------ */

#define E1000_RAH_AV        (1U << 31)  /* Address Valid              */

/* ------------------------------------------------------------------ */
/* TX descriptor                                                       */
/* ------------------------------------------------------------------ */

/*
 * e1000_tx_desc_t - Legacy TX descriptor (16 bytes)
 *
 * The hardware reads one descriptor per packet.  addr points to a
 * physically-addressable packet buffer; length is the byte count;
 * cmd controls special processing; status.DD is set by hardware when
 * the descriptor has been processed.
 */
typedef struct {
    uint64_t addr;      /* Physical address of the TX buffer          */
    uint16_t length;    /* Packet length in bytes                     */
    uint8_t  cso;       /* Checksum offset (0 = unused)               */
    uint8_t  cmd;       /* Command bits (see E1000_TXD_CMD_*)         */
    uint8_t  status;    /* Status bits (DD = bit 0)                   */
    uint8_t  css;       /* Checksum start (0 = unused)                */
    uint16_t special;   /* Reserved / VLAN tag                        */
} __attribute__((packed)) e1000_tx_desc_t;

/* TX command bits */
#define E1000_TXD_CMD_EOP   (1U << 0)  /* End Of Packet               */
#define E1000_TXD_CMD_IFCS  (1U << 1)  /* Insert FCS / CRC            */
#define E1000_TXD_CMD_RS    (1U << 3)  /* Report Status (set DD)      */

/* TX status bits */
#define E1000_TXD_STAT_DD   (1U << 0)  /* Descriptor Done             */

/* ------------------------------------------------------------------ */
/* RX descriptor                                                       */
/* ------------------------------------------------------------------ */

/*
 * e1000_rx_desc_t - Legacy RX descriptor (16 bytes)
 *
 * The driver pre-fills addr with a buffer the hardware can DMA into.
 * When a frame arrives the hardware fills length, status, and errors,
 * then sets status.DD to signal the descriptor is ready to consume.
 */
typedef struct {
    uint64_t addr;      /* Physical address of the RX buffer          */
    uint16_t length;    /* Received frame length (set by hardware)    */
    uint16_t checksum;  /* Frame checksum (set by hardware)           */
    uint8_t  status;    /* Status bits (DD = bit 0, EOP = bit 1)      */
    uint8_t  errors;    /* Error bits                                 */
    uint16_t special;   /* Reserved / VLAN tag                        */
} __attribute__((packed)) e1000_rx_desc_t;

/* RX status bits */
#define E1000_RXD_STAT_DD   (1U << 0)  /* Descriptor Done             */
#define E1000_RXD_STAT_EOP  (1U << 1)  /* End Of Packet               */

/* ------------------------------------------------------------------ */
/* Descriptor ring sizes                                               */
/* ------------------------------------------------------------------ */

#define E1000_NUM_TX_DESC   16   /* Must be a multiple of 8           */
#define E1000_NUM_RX_DESC   16   /* Must be a multiple of 8           */

/* ------------------------------------------------------------------ */
/* Public driver instance                                              */
/* ------------------------------------------------------------------ */

/*
 * e1000_driver - nic_driver_t instance for the Intel e1000.
 *
 * Expose via extern so nic_stub.c can probe for it in nic_init().
 * In TEST_HOST mode e1000_driver.init() always returns false.
 */
extern nic_driver_t e1000_driver;

#endif /* VESPER_E1000_H */
