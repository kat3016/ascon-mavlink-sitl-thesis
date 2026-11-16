#pragma once

/*
  AP_MAVCrypt: Ascon-AEAD128 (NIST SP 800-232) protection of every MAVLink
  frame sent or received on a MAVLink channel.

  Send path (GCS_MAVLink.cpp):
    comm_send_lock()   -> mavcrypt_tx_begin(): start capturing the frame
    comm_send_buffer() -> mavcrypt_tx_append(): header, payload, CRC, signature
    comm_send_unlock() -> mavcrypt_tx_end(): seal the whole frame, one write
  Receive path (GCS_MAVLINK::update_receive in GCS_Common.cpp):
    every byte goes through mavcrypt_rx_push()/mavcrypt_rx_poll(); only
    authentic, fresh frames reach the normal MAVLink parser.

  Frame: | header (clear, AD) | E(payload||CRC[||sig]) | nonce 16 B | tag 16 B |
 */

#include "AP_MAVCrypt_config.h"

#include <stdint.h>

#if AP_MAVCRYPT_ENABLED

#include "mavcrypt_core.h"  // MC_OVERHEAD: 32 B (ascon) or 28 B (aesgcm/chacha)

#define MAVCRYPT_TX_OVERHEAD MC_OVERHEAD    // nonce + tag
#define MAVCRYPT_PACKET_EXTRA MC_OVERHEAD   // added to GCS_MAVLINK::packet_overhead_chan()
#define MAVCRYPT_MAX_PLAIN 280    // largest clear MAVLink frame (v2 + signature)

void mavcrypt_tx_begin(uint8_t chan);
bool mavcrypt_tx_capturing(uint8_t chan);
void mavcrypt_tx_append(uint8_t chan, const uint8_t *buf, uint16_t len);
// seal the captured frame; returns the number of bytes to write from *out (0 = nothing)
uint16_t mavcrypt_tx_end(uint8_t chan, const uint8_t **out);

// returns the length of a clear frame written to out (MAVCRYPT_MAX_PLAIN bytes), or 0
uint16_t mavcrypt_rx_push(uint8_t chan, uint8_t c, uint8_t *out);
uint16_t mavcrypt_rx_poll(uint8_t chan, uint8_t *out);

#else

#define MAVCRYPT_PACKET_EXTRA 0

#endif  // AP_MAVCRYPT_ENABLED
