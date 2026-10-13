#ifndef FPC_PROTOCOL_H
#define FPC_PROTOCOL_H

/*
 * FPC "Disum" sensor protocol definitions.
 *
 * Verified on real hardware (Acer Swift 3 SF314-512, USB 10a5:e340,
 * FW 20.26.23.27) and cross-checked against the FPC DISUM protocol used by
 * the sibling part 10a5:9201.
 *
 * Transport model
 * ---------------
 *   Commands  : USB control transfers on endpoint 0
 *               bmRequestType 0x40 = host->device (OUT)
 *               bmRequestType 0xc0 = device->host (IN)
 *               bRequest       = one of enum fpc_cmd
 *               wValue/wIndex  = command specific (see call sites)
 *   Events    : a single bulk IN endpoint (0x81 on e340, 0x82 on 9201)
 *
 * Every bulk packet is framed as a 12-byte header followed by a payload:
 *
 *     struct fpc_event { u32 code; u32 len; u32 unknown; };
 *
 * `len` is the TOTAL packet length (header + payload).
 *
 * Endianness: the e340 firmware serialises these fields LITTLE-ENDIAN.
 * (The 9201 firmware used big-endian, hence the two differ -- do not assume.)
 *
 * After CMD_INIT the device enters an encrypted session: bulk packets with
 * code == EVT_TLS carry TLS records. The host acts as the TLS *client* and the
 * device as the TLS *server*, using a pre-shared key derived from the blob
 * returned by CMD_GET_TLS_KEY. (The sibling 10a5:9201 uses the opposite roles,
 * so do not assume.) On this e340 unit the finger/image events then arrive as
 * plain framed packets (not wrapped in EVT_TLS).
 */

#include <stdint.h>

/* USB Hardware IDs */
#define FPC_USB_VID              0x10a5
#define FPC_USB_PID_ACER         0xe340  /* Acer Swift series (Swift 3 SF314-512) */
#define FPC_USB_PID_HONOR        0xa900  /* Honor MagicBook series */

/* USB control transfer bmRequestType */
#define FPC_REQTYPE_VENDOR_OUT   0x40  /* Host-to-Device | Vendor | Device */
#define FPC_REQTYPE_VENDOR_IN    0xc0  /* Device-to-Host | Vendor | Device */

/* Command codes (bRequest), verified from the Windows UMDF driver. */
enum fpc_cmd {
    CMD_INIT                     = 0x01,
    CMD_ARM                      = 0x02,
    CMD_ABORT                    = 0x03,
    CMD_BOOT0_REQ                = 0x04,
    CMD_TLS_INIT                 = 0x05,
    CMD_TLS_DATA                 = 0x06,
    CMD_INDICATE_S_STATE         = 0x08,
    CMD_GET_IMG                  = 0x09,
    CMD_GET_DEAD_PIXELS          = 0x0a,
    CMD_GET_TLS_KEY              = 0x0b,
    CMD_GET_KPI                  = 0x0c,
    CMD_SET_TLS_KEY              = 0x0d,
    CMD_FINISH_ENROLL            = 0x0e,
    CMD_FUSE_DEVICE              = 0x10,
    CMD_FINGERPRINT_SESSION_OFF  = 0x12,
    CMD_REFRESH_SENSOR           = 0x20,
    CMD_GET_FW_VERSION           = 0x30,
    CMD_GET_HW_UNIQUE_ID         = 0x31,
    CMD_FLUSH_KEYS               = 0x32,
    CMD_PASSTHRU_INT_CONTROL     = 0x40,
    CMD_PASSTHRU_CS_CONTROL      = 0x41,
    CMD_PASSTHRU_INT_VALUE_OUT   = 0x42,
    CMD_PASSTHRU_TO_SPI          = 0x43,
    CMD_PASSTHRU_FROM_SPI        = 0x44,
    CMD_PASSTHRU_INT_VALUE_IN    = 0x45,
    GET_STATE                    = 0x50,
    CMD_GET_MSOS                 = 0xaa,
};

/* Event codes (first u32 of a framed packet). */
enum fpc_event {
    EVT_HELLO                    = 0x01,
    EVT_INIT_RESULT              = 0x02,
    EVT_ARM_RESULT               = 0x03,
    EVT_DEAD_PIXEL_REPORT        = 0x04,
    EVT_TLS                      = 0x05,  /* payload is a TLS record */
    EVT_FINGER_DWN               = 0x06,
    EVT_FINGER_UP                = 0x07,
    EVT_IMG                      = 0x08,
    EVT_USB_LOGS                 = 0x09,
    EVT_TLS_KEY                  = 0x0a,
    EVT_REFRESH_SENSOR           = 0x20,
};

/* Framed bulk packet header. Fields are little-endian on the e340. */
#define FPC_EVENT_HDR_SIZE       12

#pragma pack(push, 1)
struct fpc_event_hdr {
    uint32_t code;
    uint32_t len;      /* total packet length incl. this header */
    uint32_t unknown;
};

/* Blob returned by CMD_GET_TLS_KEY (see probe: magic 0x0dec0ded). */
struct fpc_tls_key {
    uint32_t magic;        /* 0x0dec0ded */
    uint32_t key_offset;
    uint32_t key_len;
    uint32_t aad_offset;
    uint32_t aad_len;
    uint32_t sig_offset;
    uint32_t sig_len;
    /* variable data follows; "FPC TLS Keys" AAD + sealed key + HMAC sig */
};
#pragma pack(pop)

/* Raw capacitive frame geometry. An EVT_IMG payload is a 22-byte frame header
 * (which embeds the 0x112f1117 capture id) followed by the pixel bytes. */
#define FPC_IMG_HDR_SIZE         22
#define FPC_SENSOR_WIDTH         128
#define FPC_SENSOR_HEIGHT        88
#define FPC_IMAGE_BYTES          (FPC_SENSOR_WIDTH * FPC_SENSOR_HEIGHT)  /* 11264 */

/* 4-byte session / capture ids exchanged with CMD_INIT / CMD_ARM. */
#define FPC_INIT_MAGIC           0x10, 0x2f, 0x11, 0x17
#define FPC_ARM_MAGIC            0x11, 0x2f, 0x11, 0x17
#define FPC_DISARM_MAGIC         0x12, 0x2f, 0x11, 0x17

/* TLS key derivation constants (NUL terminator included in the length). */
#define FPC_HMAC_KEY_STR         "FPC_HMAC_KEY"
#define FPC_HMAC_KEY_LEN         13
#define FPC_SEALING_KEY_STR      "FPC_SEALING_KEY"
#define FPC_SEALING_KEY_LEN      16

static inline const char *fpc_cmd_to_str(uint8_t cmd) {
    switch (cmd) {
        case CMD_INIT: return "CMD_INIT";
        case CMD_ARM: return "CMD_ARM";
        case CMD_ABORT: return "CMD_ABORT";
        case CMD_BOOT0_REQ: return "CMD_BOOT0_REQ";
        case CMD_TLS_INIT: return "CMD_TLS_INIT";
        case CMD_TLS_DATA: return "CMD_TLS_DATA";
        case CMD_INDICATE_S_STATE: return "CMD_INDICATE_S_STATE";
        case CMD_GET_IMG: return "CMD_GET_IMG";
        case CMD_GET_DEAD_PIXELS: return "CMD_GET_DEAD_PIXELS";
        case CMD_GET_TLS_KEY: return "CMD_GET_TLS_KEY";
        case CMD_GET_KPI: return "CMD_GET_KPI";
        case CMD_SET_TLS_KEY: return "CMD_SET_TLS_KEY";
        case CMD_FINISH_ENROLL: return "CMD_FINISH_ENROLL";
        case CMD_FUSE_DEVICE: return "CMD_FUSE_DEVICE";
        case CMD_FINGERPRINT_SESSION_OFF: return "CMD_FINGERPRINT_SESSION_OFF";
        case CMD_REFRESH_SENSOR: return "CMD_REFRESH_SENSOR";
        case CMD_GET_FW_VERSION: return "CMD_GET_FW_VERSION";
        case CMD_GET_HW_UNIQUE_ID: return "CMD_GET_HW_UNIQUE_ID";
        case CMD_FLUSH_KEYS: return "CMD_FLUSH_KEYS";
        case CMD_PASSTHRU_INT_CONTROL: return "CMD_PASSTHRU_INT_CONTROL";
        case CMD_PASSTHRU_CS_CONTROL: return "CMD_PASSTHRU_CS_CONTROL";
        case CMD_PASSTHRU_INT_VALUE_OUT: return "CMD_PASSTHRU_INT_VALUE_OUT";
        case CMD_PASSTHRU_TO_SPI: return "CMD_PASSTHRU_TO_SPI";
        case CMD_PASSTHRU_FROM_SPI: return "CMD_PASSTHRU_FROM_SPI";
        case CMD_PASSTHRU_INT_VALUE_IN: return "CMD_PASSTHRU_INT_VALUE_IN";
        case GET_STATE: return "GET_STATE";
        case CMD_GET_MSOS: return "CMD_GET_MSOS";
        default: return "UNKNOWN_CMD";
    }
}

static inline const char *fpc_event_to_str(uint32_t evt) {
    switch (evt) {
        case EVT_HELLO: return "EVT_HELLO";
        case EVT_INIT_RESULT: return "EVT_INIT_RESULT";
        case EVT_ARM_RESULT: return "EVT_ARM_RESULT";
        case EVT_DEAD_PIXEL_REPORT: return "EVT_DEAD_PIXEL_REPORT";
        case EVT_TLS: return "EVT_TLS";
        case EVT_FINGER_DWN: return "EVT_FINGER_DWN";
        case EVT_FINGER_UP: return "EVT_FINGER_UP";
        case EVT_IMG: return "EVT_IMG";
        case EVT_USB_LOGS: return "EVT_USB_LOGS";
        case EVT_TLS_KEY: return "EVT_TLS_KEY";
        case EVT_REFRESH_SENSOR: return "EVT_REFRESH_SENSOR";
        default: return "UNKNOWN_EVT";
    }
}

#endif /* FPC_PROTOCOL_H */
