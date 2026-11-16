/*
 * Ascon-AEAD128 from ascon-c (crypto_aead/asconaead128/opt32, CC0), compiled
 * unmodified. The sources live in ascon/ so that waf does not compile them
 * directly; ArduPilot's strict warnings (-Werror=undef, -Wcast-align=strict)
 * are relaxed only for this translation unit.
 */
#include "mavcrypt_core.h"  /* AP_MAVCRYPT_ALG, MC_ALG_* */

#if defined(AP_MAVCRYPT_ENABLED) && AP_MAVCRYPT_ENABLED && (AP_MAVCRYPT_ALG == MC_ALG_ASCON)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "ascon/aead.c"
#include "ascon/permutations.c"

#pragma GCC diagnostic pop

#endif
