/* MAMBA-Viper implementation and implementation support layer where applicable.
 * FO KEM using SHAKE128 hashes/KDF and deterministic re-encryption.
 */

#include "api.h"
#include "fips202.h"
#include "random.h"
#include "verify.h"
#include "viper.h"
#include <string.h>

static void h32(unsigned char out[32], const unsigned char *in, unsigned long long inlen) {
  shake128(out, 32, in, inlen);
}

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
  unsigned char rho[32], sseed[32];
  random_bytes(rho, 32);
  random_bytes(sseed, 32);
  viper_pke_keypair(pk, sk, rho, sseed);
  memcpy(sk + VIPER_SECRETKEY_PKE_BYTES, pk, VIPER_PUBLICKEYBYTES);
  h32(sk + VIPER_SECRETKEY_PKE_BYTES + VIPER_PUBLICKEYBYTES, pk, VIPER_PUBLICKEYBYTES);
  random_bytes(sk + VIPER_SECRETKEY_PKE_BYTES + VIPER_PUBLICKEYBYTES + 32, 32);
  return 0;
}

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
  unsigned char m[32], hpk[32], buf[64], kr[64], hct[32], omega[64], kdfin[64];
  random_bytes(m, 32);
  h32(m, m, 32);
  h32(hpk, pk, VIPER_PUBLICKEYBYTES);
  memcpy(buf, m, 32);
  memcpy(buf + 32, hpk, 32);
  shake128(kr, 64, buf, 64); /* kr[0:31]=kbar, kr[32:63]=sigma */
  h32(omega + 32, kr, 32);   /* public mu bound to kbar */
  memcpy(omega, kr + 32, 32);
  viper_pke_enc(ct, pk, m, omega);
  h32(hct, ct, VIPER_CIPHERTEXTBYTES);
  memcpy(kdfin, kr, 32);
  memcpy(kdfin + 32, hct, 32);
  h32(ss, kdfin, 64);
  return 0;
}

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
  unsigned char m[32], buf[64], kr[64], hct[32], kdfin[64];
  const unsigned char *pk = sk + VIPER_SECRETKEY_PKE_BYTES;
  const unsigned char *hpk = sk + VIPER_SECRETKEY_PKE_BYTES + VIPER_PUBLICKEYBYTES;
  const unsigned char *z = hpk + 32;
  viper_pke_dec(m, sk, ct);
  memcpy(buf, m, 32);
  memcpy(buf + 32, hpk, 32);
  shake128(kr, 64, buf, 64);
  int ok = viper_reencrypt_check(ct, pk, m, kr + 32);
  h32(hct, ct, VIPER_CIPHERTEXTBYTES);
  memcpy(kdfin, ok ? kr : z, 32);
  memcpy(kdfin + 32, hct, 32);
  h32(ss, kdfin, 64);
  return 0;
}
