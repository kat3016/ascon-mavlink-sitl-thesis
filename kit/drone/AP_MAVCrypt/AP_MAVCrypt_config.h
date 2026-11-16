#pragma once

// Ascon-AEAD128 protection of MAVLink frames (thesis kit).
// Enable with: ./waf configure --board <board> --define AP_MAVCRYPT_ENABLED=1
#ifndef AP_MAVCRYPT_ENABLED
#define AP_MAVCRYPT_ENABLED 0
#endif

// Write encryption/decryption timing to MAVCRYPT_STATS_PATH every N frames
// (0 = off). Only for the dedicated timing runs: it adds file I/O that the
// other binaries do not have.
#ifndef MAVCRYPT_STATS_EVERY
#define MAVCRYPT_STATS_EVERY 0
#endif

#ifndef MAVCRYPT_STATS_PATH
#define MAVCRYPT_STATS_PATH "mavcrypt_stats.csv"
#endif

// highest MAVLink channel number handled (MAVLINK_COMM_NUM_BUFFERS is 16 on SITL)
#ifndef MAVCRYPT_MAX_CHANS
#define MAVCRYPT_MAX_CHANS 16
#endif
