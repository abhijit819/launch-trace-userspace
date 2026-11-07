/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LAUNCHTRACE_UAPI_H
#define LAUNCHTRACE_UAPI_H

#include <stdint.h>
#include <sys/ioctl.h>

#define LT_IOCTL_MAGIC          'L'
#define LT_IOCTL_SET_MAX_APPS   _IOW(LT_IOCTL_MAGIC, 1, uint32_t)
#define LT_IOCTL_START          _IO(LT_IOCTL_MAGIC, 2)
#define LT_IOCTL_STOP           _IO(LT_IOCTL_MAGIC, 3)
#define LT_IOCTL_ACK            _IOW(LT_IOCTL_MAGIC, 4, uint64_t)

/* Numeric value used by the current kernel ABI after le32toh(). */
#define LT_WIRE_MAGIC           UINT32_C(0x4352544c)
#define LT_WIRE_VERSION         1U
#define LT_WIRE_HEADER_BYTES    64U
#define LT_WIRE_DEVICE_BYTES    16U
#define LT_WIRE_RECORD_BYTES    32U

#define LT_DB_MAGIC             "LTDBv1\0\0"
#define LT_DB_MAGIC_BYTES       8U
#define LT_DB_VERSION           1U
#define LT_DB_HEADER_BYTES      24U
#define LT_DB_ENTRY_HEADER_BYTES 8U

#endif
