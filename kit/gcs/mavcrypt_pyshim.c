/* Compiled only into build/libmavcrypt.so: lets the Python binding check that
   its ctypes structures have the same size as the C ones. */
#include "mavcrypt_core.h"

unsigned mc_sizeof_tx(void) { return (unsigned)sizeof(mc_tx_t); }
unsigned mc_sizeof_rx(void) { return (unsigned)sizeof(mc_rx_t); }

/* Algorithm metadata so the Python binding can size its ctypes structures
 * from the library actually loaded, instead of hard-coding per-algorithm
 * constants that could drift out of sync with this header. */
unsigned mc_key_len(void) { return MC_KEY_LEN; }
unsigned mc_prefix_len(void) { return MC_PREFIX_LEN; }
unsigned mc_nonce_len(void) { return MC_NONCE_LEN; }
unsigned mc_overhead(void) { return MC_OVERHEAD; }
unsigned mc_max_frame(void) { return MC_MAX_FRAME; }
unsigned mc_alg_id(void) { return AP_MAVCRYPT_ALG; }
