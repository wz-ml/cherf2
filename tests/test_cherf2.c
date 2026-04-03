#ifndef __APPLE__
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <monocypher.h>

#include "greatest.h"

/* Suppress warn_unused_result for test helpers */
#pragma GCC diagnostic ignored "-Wunused-result"

/* Pull in project headers. We avoid including helpers.h directly
 * because it depends on braid.h; instead we redeclare the pure
 * functions we need and link against helpers.o.                  */
#include "../packet.h"
#include "../config.h"

/* Re-define ts2ms macro (from helpers.h) to avoid braid dependency */
#define ts2ms(ts) ((uint64_t)(ts.tv_sec) * 1000 + (ts.tv_nsec) / 1000000)

/* Declarations of the functions under test (from helpers.c) */
extern void  rand_buf(size_t len, uint8_t buf[static len]);
extern int   read_key(uint8_t key[static 32], const char *filename);
extern char *key2hex(char dst[static 64], uint8_t key[static 32]);
extern void  gen_keys(const uint8_t s_sk[static 32], const uint8_t s_pk[static 32],
                      const uint8_t r_pk[32],
                      uint8_t e_pk[static 32], uint8_t es[static 32], uint8_t ss[static 32]);

/* ================================================================
 * SUITE: Packet structure sizes and macros
 * ================================================================ */

TEST packet_header_size(void) {
  ASSERT_EQ(17, sizeof(Header));
  PASS();
}

TEST packet_handshake_data_size(void) {
  ASSERT_EQ(64, sizeof(HandshakeData));
  PASS();
}

TEST packet_attach_data_size(void) {
  /* 64 (hs) + 32 (target) + 16 (mac2) = 112 */
  ASSERT_EQ(112, sizeof(AttachData));
  PASS();
}

TEST packet_advertise_data_size(void) {
  /* 64 (hs) + 8 (ts_ms) + 16 (mac2) = 88 */
  ASSERT_EQ(88, sizeof(AdvertiseData));
  PASS();
}

TEST packet_connect_data_size(void) {
  ASSERT_EQ(6, sizeof(ConnectData));
  PASS();
}

TEST packet_error_data_size(void) {
  ASSERT_EQ(1, sizeof(ErrorData));
  PASS();
}

TEST packet_max_is_attach(void) {
  /* PACKET_MAX should be header + largest payload (AttachData) */
  ASSERT_EQ(sizeof(Header) + sizeof(AttachData), PACKET_MAX);
  PASS();
}

TEST head_macro_points_to_start(void) {
  uint8_t buf[PACKET_MAX];
  ASSERT_EQ((void *)buf, (void *)HEAD(buf));
  PASS();
}

TEST data_macro_points_past_header(void) {
  uint8_t buf[PACKET_MAX];
  ASSERT_EQ((void *)(buf + sizeof(Header)), (void *)DATA(buf, uint8_t));
  PASS();
}

TEST data_sz_attach(void) {
  uint8_t p[PACKET_MAX] = {0};
  HEAD(p)->type = ATTACH;
  ASSERT_EQ(sizeof(AttachData), data_sz(p));
  PASS();
}

TEST data_sz_advertise(void) {
  uint8_t p[PACKET_MAX] = {0};
  HEAD(p)->type = ADVERTISE;
  ASSERT_EQ(sizeof(AdvertiseData), data_sz(p));
  PASS();
}

TEST data_sz_connect(void) {
  uint8_t p[PACKET_MAX] = {0};
  HEAD(p)->type = CONNECT;
  ASSERT_EQ(sizeof(ConnectData), data_sz(p));
  PASS();
}

TEST data_sz_keepalive(void) {
  uint8_t p[PACKET_MAX] = {0};
  HEAD(p)->type = KEEPALIVE;
  ASSERT_EQ(1, data_sz(p));
  PASS();
}

TEST data_sz_error(void) {
  uint8_t p[PACKET_MAX] = {0};
  HEAD(p)->type = ERROR;
  ASSERT_EQ(sizeof(ErrorData), data_sz(p));
  PASS();
}

TEST packet_sz_equals_header_plus_data(void) {
  uint8_t p[PACKET_MAX] = {0};

  HEAD(p)->type = ATTACH;
  ASSERT_EQ(sizeof(Header) + sizeof(AttachData), packet_sz(p));

  HEAD(p)->type = ADVERTISE;
  ASSERT_EQ(sizeof(Header) + sizeof(AdvertiseData), packet_sz(p));

  HEAD(p)->type = CONNECT;
  ASSERT_EQ(sizeof(Header) + sizeof(ConnectData), packet_sz(p));

  HEAD(p)->type = ERROR;
  ASSERT_EQ(sizeof(Header) + sizeof(ErrorData), packet_sz(p));

  PASS();
}

TEST packet_type_enum_values(void) {
  ASSERT_EQ(0, ATTACH);
  ASSERT_EQ(1, ADVERTISE);
  ASSERT_EQ(2, CONNECT);
  ASSERT_EQ(3, KEEPALIVE);
  ASSERT_EQ(0xFF, ERROR);
  PASS();
}

TEST error_code_enum_values(void) {
  ASSERT_EQ(0, ERROR_UNAUTHORIZED);
  ASSERT_EQ(1, ERROR_NOT_FOUND);
  ASSERT_EQ(2, ERROR_INVALID_TIMESTAMP);
  ASSERT_EQ(3, ERROR_TOO_MANY_ADVERTS);
  PASS();
}

SUITE(packet_suite) {
  RUN_TEST(packet_header_size);
  RUN_TEST(packet_handshake_data_size);
  RUN_TEST(packet_attach_data_size);
  RUN_TEST(packet_advertise_data_size);
  RUN_TEST(packet_connect_data_size);
  RUN_TEST(packet_error_data_size);
  RUN_TEST(packet_max_is_attach);
  RUN_TEST(head_macro_points_to_start);
  RUN_TEST(data_macro_points_past_header);
  RUN_TEST(data_sz_attach);
  RUN_TEST(data_sz_advertise);
  RUN_TEST(data_sz_connect);
  RUN_TEST(data_sz_keepalive);
  RUN_TEST(data_sz_error);
  RUN_TEST(packet_sz_equals_header_plus_data);
  RUN_TEST(packet_type_enum_values);
  RUN_TEST(error_code_enum_values);
}

/* ================================================================
 * SUITE: key2hex
 * ================================================================ */

TEST key2hex_zero_key(void) {
  char dst[65] = {0};
  uint8_t key[32] = {0};
  key2hex(dst, key);
  ASSERT_STR_EQ("0000000000000000000000000000000000000000000000000000000000000000", dst);
  PASS();
}

TEST key2hex_ff_key(void) {
  char dst[65] = {0};
  uint8_t key[32];
  memset(key, 0xFF, 32);
  key2hex(dst, key);
  ASSERT_STR_EQ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", dst);
  PASS();
}

TEST key2hex_known_value(void) {
  char dst[65] = {0};
  /* 0x00 0x01 0x02 ... 0x1F */
  uint8_t key[32];
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  key2hex(dst, key);
  ASSERT_STR_EQ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", dst);
  PASS();
}

TEST key2hex_returns_dst(void) {
  char dst[65] = {0};
  uint8_t key[32] = {0};
  char *ret = key2hex(dst, key);
  ASSERT_EQ(dst, ret);
  PASS();
}

TEST key2hex_single_nibble_values(void) {
  char dst[65] = {0};
  uint8_t key[32] = {0};
  /* Test boundary nibble values: 0x9A has high nibble 9, low nibble A */
  key[0] = 0x9A;
  key[1] = 0xBF;
  key2hex(dst, key);
  ASSERT_EQ('9', dst[0]);
  ASSERT_EQ('A', dst[1]);
  ASSERT_EQ('B', dst[2]);
  ASSERT_EQ('F', dst[3]);
  PASS();
}

SUITE(key2hex_suite) {
  RUN_TEST(key2hex_zero_key);
  RUN_TEST(key2hex_ff_key);
  RUN_TEST(key2hex_known_value);
  RUN_TEST(key2hex_returns_dst);
  RUN_TEST(key2hex_single_nibble_values);
}

/* ================================================================
 * SUITE: rand_buf
 * ================================================================ */

TEST rand_buf_fills_nonzero(void) {
  uint8_t buf[64] = {0};
  rand_buf(sizeof(buf), buf);
  /* Probability of 64 zero bytes from urandom is ~0 */
  int all_zero = 1;
  for (size_t i = 0; i < sizeof(buf); i++)
    if (buf[i] != 0) { all_zero = 0; break; }
  ASSERT_FALSE(all_zero);
  PASS();
}

TEST rand_buf_different_each_call(void) {
  uint8_t a[32], b[32];
  rand_buf(32, a);
  rand_buf(32, b);
  ASSERT(memcmp(a, b, 32) != 0);
  PASS();
}

TEST rand_buf_fills_exact_length(void) {
  uint8_t buf[128];
  memset(buf, 0xAA, sizeof(buf));
  /* Fill only the first 32 bytes */
  rand_buf(32, buf);
  /* Sentinel bytes at position 32+ should still be 0xAA
   * (unless rand_buf overwrites them, which would be a bug) */
  int sentinel_intact = 1;
  for (size_t i = 32; i < sizeof(buf); i++)
    if (buf[i] != 0xAA) { sentinel_intact = 0; break; }
  ASSERT(sentinel_intact);
  PASS();
}

SUITE(rand_buf_suite) {
  RUN_TEST(rand_buf_fills_nonzero);
  RUN_TEST(rand_buf_different_each_call);
  RUN_TEST(rand_buf_fills_exact_length);
}

/* ================================================================
 * SUITE: read_key
 * ================================================================ */

static char tmpdir[256];

static void read_key_setup(void *arg) {
  (void)arg;
  snprintf(tmpdir, sizeof(tmpdir), "/tmp/cherf2_test_XXXXXX");
  if (!mkdtemp(tmpdir)) tmpdir[0] = 0;
}

static void read_key_teardown(void *arg) {
  (void)arg;
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
  system(cmd);
}

static void pushd(const char *dir, char *save, size_t sz) {
  if (!getcwd(save, sz)) save[0] = 0;
  if (chdir(dir)) save[0] = 0;
}
static void popd(const char *save) { if (save[0]) chdir(save); }

TEST read_key_valid_file(void) {
  char path[512];
  uint8_t written[32], readback[32];
  FILE *f;

  rand_buf(32, written);
  snprintf(path, sizeof(path), "%s/testkey", tmpdir);
  f = fopen(path, "wb");
  ASSERT(f != NULL);
  ASSERT_EQ(32, fwrite(written, 1, 32, f));
  fclose(f);

  char oldcwd[512];
  pushd(tmpdir, oldcwd, sizeof(oldcwd));

  int rc = read_key(readback, "testkey");
  popd(oldcwd);

  ASSERT_EQ(0, rc);
  ASSERT_MEM_EQ(written, readback, 32);
  PASS();
}

TEST read_key_nonexistent_file(void) {
  char oldcwd[512];
  pushd(tmpdir, oldcwd, sizeof(oldcwd));

  uint8_t key[32];
  int rc = read_key(key, "nonexistent_key_file_xyz");
  int saved_errno = errno;
  popd(oldcwd);

  ASSERT_EQ(-1, rc);
  ASSERT_EQ(ENOENT, saved_errno);
  PASS();
}

TEST read_key_short_file(void) {
  char path[512];
  FILE *f;

  snprintf(path, sizeof(path), "%s/shortkey", tmpdir);
  f = fopen(path, "wb");
  ASSERT(f != NULL);
  /* Write only 16 bytes instead of 32 */
  uint8_t data[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  fwrite(data, 1, 16, f);
  fclose(f);

  char oldcwd[512];
  pushd(tmpdir, oldcwd, sizeof(oldcwd));

  uint8_t key[32];
  int rc = read_key(key, "shortkey");
  popd(oldcwd);

  ASSERT_EQ(-1, rc);
  PASS();
}

TEST read_key_exact_32_bytes(void) {
  char path[512];
  uint8_t written[32], readback[32];
  FILE *f;

  for (int i = 0; i < 32; i++) written[i] = (uint8_t)i;
  snprintf(path, sizeof(path), "%s/exact32", tmpdir);
  f = fopen(path, "wb");
  ASSERT(f != NULL);
  fwrite(written, 1, 32, f);
  fclose(f);

  char oldcwd[512];
  pushd(tmpdir, oldcwd, sizeof(oldcwd));

  int rc = read_key(readback, "exact32");
  popd(oldcwd);

  ASSERT_EQ(0, rc);
  ASSERT_MEM_EQ(written, readback, 32);
  PASS();
}

SUITE(read_key_suite) {
  SET_SETUP(read_key_setup, NULL);
  SET_TEARDOWN(read_key_teardown, NULL);
  RUN_TEST(read_key_valid_file);
  RUN_TEST(read_key_nonexistent_file);
  RUN_TEST(read_key_short_file);
  RUN_TEST(read_key_exact_32_bytes);
}

/* ================================================================
 * SUITE: ts2ms macro
 * ================================================================ */

TEST ts2ms_zero(void) {
  struct timespec ts = {0, 0};
  ASSERT_EQ(0ULL, ts2ms(ts));
  PASS();
}

TEST ts2ms_one_second(void) {
  struct timespec ts = {1, 0};
  ASSERT_EQ(1000ULL, ts2ms(ts));
  PASS();
}

TEST ts2ms_one_ms(void) {
  struct timespec ts = {0, 1000000};
  ASSERT_EQ(1ULL, ts2ms(ts));
  PASS();
}

TEST ts2ms_combined(void) {
  struct timespec ts = {5, 500000000};
  ASSERT_EQ(5500ULL, ts2ms(ts));
  PASS();
}

TEST ts2ms_large_value(void) {
  struct timespec ts = {1700000000, 123000000};
  ASSERT_EQ(1700000000123ULL, ts2ms(ts));
  PASS();
}

TEST ts2ms_nanosecond_truncation(void) {
  /* 999999 ns = 0.999999 ms → should truncate to 0 ms */
  struct timespec ts = {0, 999999};
  ASSERT_EQ(0ULL, ts2ms(ts));
  PASS();
}

TEST ts2ms_just_under_one_ms(void) {
  struct timespec ts = {0, 1999999};
  ASSERT_EQ(1ULL, ts2ms(ts));
  PASS();
}

SUITE(ts2ms_suite) {
  RUN_TEST(ts2ms_zero);
  RUN_TEST(ts2ms_one_second);
  RUN_TEST(ts2ms_one_ms);
  RUN_TEST(ts2ms_combined);
  RUN_TEST(ts2ms_large_value);
  RUN_TEST(ts2ms_nanosecond_truncation);
  RUN_TEST(ts2ms_just_under_one_ms);
}

/* ================================================================
 * SUITE: gen_keys - key generation and derivation
 * ================================================================ */

TEST gen_keys_outputs_nonzero(void) {
  uint8_t s_sk[32], s_pk[32], r_sk[32], r_pk[32];
  uint8_t e_pk[32], es[32], ss[32];
  uint8_t zero[32] = {0};

  rand_buf(32, s_sk);
  crypto_x25519_public_key(s_pk, s_sk);
  rand_buf(32, r_sk);
  crypto_x25519_public_key(r_pk, r_sk);

  gen_keys(s_sk, s_pk, r_pk, e_pk, es, ss);

  ASSERT(memcmp(e_pk, zero, 32) != 0);
  ASSERT(memcmp(es, zero, 32) != 0);
  ASSERT(memcmp(ss, zero, 32) != 0);
  PASS();
}

TEST gen_keys_ephemeral_differs(void) {
  uint8_t s_sk[32], s_pk[32], r_sk[32], r_pk[32];
  uint8_t e_pk1[32], es1[32], ss1[32];
  uint8_t e_pk2[32], es2[32], ss2[32];

  rand_buf(32, s_sk);
  crypto_x25519_public_key(s_pk, s_sk);
  rand_buf(32, r_sk);
  crypto_x25519_public_key(r_pk, r_sk);

  gen_keys(s_sk, s_pk, r_pk, e_pk1, es1, ss1);
  gen_keys(s_sk, s_pk, r_pk, e_pk2, es2, ss2);

  /* Different ephemeral keys each call */
  ASSERT(memcmp(e_pk1, e_pk2, 32) != 0);
  /* es depends on ephemeral, so should also differ */
  ASSERT(memcmp(es1, es2, 32) != 0);
  PASS();
}

TEST gen_keys_es_differs_from_ss(void) {
  uint8_t s_sk[32], s_pk[32], r_sk[32], r_pk[32];
  uint8_t e_pk[32], es[32], ss[32];

  rand_buf(32, s_sk);
  crypto_x25519_public_key(s_pk, s_sk);
  rand_buf(32, r_sk);
  crypto_x25519_public_key(r_pk, r_sk);

  gen_keys(s_sk, s_pk, r_pk, e_pk, es, ss);

  ASSERT(memcmp(es, ss, 32) != 0);
  PASS();
}

/*
 * The core DH agreement test: verify that the client's gen_keys and
 * the server's derivation produce the same es and ss.
 *
 * Client side (gen_keys):
 *   es = BLAKE2b(X25519(e_sk, r_pk) || e_pk || r_pk)
 *   ss = BLAKE2b(X25519(s_sk, r_pk) || es)
 *
 * Server side (server.c handle()):
 *   es = BLAKE2b(X25519(server_sk, e_pk) || e_pk || server_pk)
 *   ss = BLAKE2b(X25519(server_sk, client_s_pk) || es)
 *
 * By DH: X25519(e_sk, server_pk) == X25519(server_sk, e_pk)
 *         X25519(client_sk, server_pk) == X25519(server_sk, client_pk)
 */
TEST gen_keys_es_agreement(void) {
  uint8_t client_sk[32], client_pk[32];
  uint8_t server_sk[32], server_pk[32];
  uint8_t e_pk[32], client_es[32], client_ss[32];
  uint8_t server_es[32], buf[96];

  rand_buf(32, client_sk);
  crypto_x25519_public_key(client_pk, client_sk);
  rand_buf(32, server_sk);
  crypto_x25519_public_key(server_pk, server_sk);

  /* Client derives keys (gen_keys uses r_pk = server_pk) */
  gen_keys(client_sk, client_pk, server_pk, e_pk, client_es, client_ss);

  /* Server derives es the same way as server.c handle() */
  crypto_x25519(buf, server_sk, e_pk);
  memcpy(buf + 32, e_pk, 32);
  memcpy(buf + 64, server_pk, 32);
  crypto_blake2b(server_es, 32, buf, 96);

  ASSERT_MEM_EQ(client_es, server_es, 32);
  PASS();
}

TEST gen_keys_ss_agreement(void) {
  uint8_t client_sk[32], client_pk[32];
  uint8_t server_sk[32], server_pk[32];
  uint8_t e_pk[32], client_es[32], client_ss[32];
  uint8_t server_es[32], server_ss[32], buf[96];

  rand_buf(32, client_sk);
  crypto_x25519_public_key(client_pk, client_sk);
  rand_buf(32, server_sk);
  crypto_x25519_public_key(server_pk, server_sk);

  gen_keys(client_sk, client_pk, server_pk, e_pk, client_es, client_ss);

  /* Server derives es */
  crypto_x25519(buf, server_sk, e_pk);
  memcpy(buf + 32, e_pk, 32);
  memcpy(buf + 64, server_pk, 32);
  crypto_blake2b(server_es, 32, buf, 96);

  /* Server derives ss using client's static public key (decrypted from packet) */
  crypto_x25519(buf, server_sk, client_pk);
  memcpy(buf + 32, server_es, 32);
  crypto_blake2b(server_ss, 32, buf, 64);

  ASSERT_MEM_EQ(client_ss, server_ss, 32);
  PASS();
}

SUITE(gen_keys_suite) {
  RUN_TEST(gen_keys_outputs_nonzero);
  RUN_TEST(gen_keys_ephemeral_differs);
  RUN_TEST(gen_keys_es_differs_from_ss);
  RUN_TEST(gen_keys_es_agreement);
  RUN_TEST(gen_keys_ss_agreement);
}

/* ================================================================
 * SUITE: AEAD encrypt/decrypt round-trips
 * ================================================================ */

TEST aead_roundtrip_basic(void) {
  uint8_t key[32], nonce[24] = {0}, mac[16];
  uint8_t plaintext[32], ciphertext[32], decrypted[32];
  uint8_t ad = 0x42;

  rand_buf(32, key);
  rand_buf(32, plaintext);

  crypto_aead_lock(ciphertext, mac, key, nonce, &ad, 1, plaintext, 32);
  int rc = crypto_aead_unlock(decrypted, mac, key, nonce, &ad, 1, ciphertext, 32);

  ASSERT_EQ(0, rc);
  ASSERT_MEM_EQ(plaintext, decrypted, 32);
  PASS();
}

TEST aead_wrong_key_fails(void) {
  uint8_t key[32], bad_key[32], nonce[24] = {0}, mac[16];
  uint8_t plaintext[32], ciphertext[32], decrypted[32];
  uint8_t ad = 0x01;

  rand_buf(32, key);
  rand_buf(32, bad_key);
  rand_buf(32, plaintext);

  crypto_aead_lock(ciphertext, mac, key, nonce, &ad, 1, plaintext, 32);
  int rc = crypto_aead_unlock(decrypted, mac, bad_key, nonce, &ad, 1, ciphertext, 32);

  ASSERT(rc != 0);
  PASS();
}

TEST aead_wrong_ad_fails(void) {
  uint8_t key[32], nonce[24] = {0}, mac[16];
  uint8_t plaintext[32], ciphertext[32], decrypted[32];
  uint8_t ad = 0x01;
  uint8_t bad_ad = 0x02;

  rand_buf(32, key);
  rand_buf(32, plaintext);

  crypto_aead_lock(ciphertext, mac, key, nonce, &ad, 1, plaintext, 32);
  int rc = crypto_aead_unlock(decrypted, mac, key, nonce, &bad_ad, 1, ciphertext, 32);

  ASSERT(rc != 0);
  PASS();
}

TEST aead_tampered_ciphertext_fails(void) {
  uint8_t key[32], nonce[24] = {0}, mac[16];
  uint8_t plaintext[32], ciphertext[32], decrypted[32];
  uint8_t ad = 0x01;

  rand_buf(32, key);
  rand_buf(32, plaintext);

  crypto_aead_lock(ciphertext, mac, key, nonce, &ad, 1, plaintext, 32);
  ciphertext[0] ^= 0x01; /* flip a bit */
  int rc = crypto_aead_unlock(decrypted, mac, key, nonce, &ad, 1, ciphertext, 32);

  ASSERT(rc != 0);
  PASS();
}

TEST aead_nonce_increment_produces_different_ciphertext(void) {
  uint8_t key[32], nonce[24] = {0}, mac1[16], mac2[16];
  uint8_t plaintext[32], ct1[32], ct2[32];

  rand_buf(32, key);
  rand_buf(32, plaintext);

  crypto_aead_lock(ct1, mac1, key, nonce, NULL, 0, plaintext, 32);
  nonce[23]++;
  crypto_aead_lock(ct2, mac2, key, nonce, NULL, 0, plaintext, 32);

  /* Different nonces must produce different ciphertext */
  ASSERT(memcmp(ct1, ct2, 32) != 0);
  PASS();
}

SUITE(aead_suite) {
  RUN_TEST(aead_roundtrip_basic);
  RUN_TEST(aead_wrong_key_fails);
  RUN_TEST(aead_wrong_ad_fails);
  RUN_TEST(aead_tampered_ciphertext_fails);
  RUN_TEST(aead_nonce_increment_produces_different_ciphertext);
}

/* ================================================================
 * SUITE: Full protocol packet encrypt/decrypt round-trips
 *
 * These simulate what the client builds and the server decrypts,
 * verifying the two-layer AEAD scheme works end-to-end.
 * ================================================================ */

TEST attach_packet_roundtrip(void) {
  uint8_t client_sk[32], client_pk[32];
  uint8_t server_sk[32], server_pk[32];
  uint8_t target_pk[32];
  uint8_t e_pk[32], es[32], ss[32];
  uint8_t p[PACKET_MAX];
  uint8_t nonce[24] = {0};

  /* Generate keys */
  rand_buf(32, client_sk);
  crypto_x25519_public_key(client_pk, client_sk);
  rand_buf(32, server_sk);
  crypto_x25519_public_key(server_pk, server_sk);
  rand_buf(32, target_pk);

  gen_keys(client_sk, client_pk, server_pk, e_pk, es, ss);

  /* Build ATTACH packet (as attach.c does) */
  HEAD(p)->type = ATTACH;
  memcpy(DATA(p, HandshakeData)->e, e_pk, 32);
  memcpy(DATA(p, HandshakeData)->s, client_pk, 32);
  memcpy(DATA(p, AttachData)->t, target_pk, 32);

  /* Layer 1: encrypt static key with es */
  crypto_aead_lock(DATA(p, HandshakeData)->s, HEAD(p)->mac, es, nonce,
                   &HEAD(p)->type, 1, DATA(p, HandshakeData)->s, 32);
  nonce[23]++;
  /* Layer 2: encrypt target key with ss */
  crypto_aead_lock(DATA(p, AttachData)->t, DATA(p, AttachData)->mac2, ss, nonce,
                   NULL, 0, DATA(p, AttachData)->t, 32);
  nonce[23]++;

  /* === Server-side decryption (as server.c does) === */
  uint8_t srv_es[32], srv_ss[32], srv_nonce[24] = {0};
  uint8_t buf[96];
  HandshakeData *hs = DATA(p, HandshakeData);

  /* Server derives es */
  crypto_x25519(buf, server_sk, hs->e);
  memcpy(buf + 32, hs->e, 32);
  memcpy(buf + 64, server_pk, 32);
  crypto_blake2b(srv_es, 32, buf, 96);

  /* Layer 1 unlock */
  int rc1 = crypto_aead_unlock(hs->s, HEAD(p)->mac, srv_es, srv_nonce,
                                &HEAD(p)->type, 1, hs->s, 32);
  ASSERT_EQ(0, rc1);
  srv_nonce[23]++;

  /* Verify decrypted static key matches client's public key */
  ASSERT_MEM_EQ(client_pk, hs->s, 32);

  /* Server derives ss */
  crypto_x25519(buf, server_sk, hs->s);
  memcpy(buf + 32, srv_es, 32);
  crypto_blake2b(srv_ss, 32, buf, 64);

  /* Layer 2 unlock */
  AttachData *ad = DATA(p, AttachData);
  int rc2 = crypto_aead_unlock(ad->t, ad->mac2, srv_ss, srv_nonce,
                                NULL, 0, ad->t, 32);
  ASSERT_EQ(0, rc2);

  /* Verify decrypted target key */
  ASSERT_MEM_EQ(target_pk, ad->t, 32);

  PASS();
}

TEST advertise_packet_roundtrip(void) {
  uint8_t client_sk[32], client_pk[32];
  uint8_t server_sk[32], server_pk[32];
  uint8_t e_pk[32], es[32], ss[32];
  uint8_t p[PACKET_MAX];
  uint8_t nonce[24] = {0};
  struct timespec ts;

  rand_buf(32, client_sk);
  crypto_x25519_public_key(client_pk, client_sk);
  rand_buf(32, server_sk);
  crypto_x25519_public_key(server_pk, server_sk);

  gen_keys(client_sk, client_pk, server_pk, e_pk, es, ss);

  /* Build ADVERTISE packet */
  HEAD(p)->type = ADVERTISE;
  memcpy(DATA(p, HandshakeData)->e, e_pk, 32);
  memcpy(DATA(p, HandshakeData)->s, client_pk, 32);
  clock_gettime(CLOCK_REALTIME, &ts);
  uint64_t orig_ts = ts2ms(ts);
  DATA(p, AdvertiseData)->ts_ms = orig_ts;

  /* Layer 1: encrypt static key with es */
  crypto_aead_lock(DATA(p, HandshakeData)->s, HEAD(p)->mac, es, nonce,
                   &HEAD(p)->type, 1, DATA(p, HandshakeData)->s, 32);
  nonce[23]++;
  /* Layer 2: encrypt timestamp with ss */
  crypto_aead_lock((uint8_t *)&DATA(p, AdvertiseData)->ts_ms,
                   DATA(p, AdvertiseData)->mac2, ss, nonce, NULL, 0,
                   (uint8_t *)&DATA(p, AdvertiseData)->ts_ms,
                   sizeof(DATA(p, AdvertiseData)->ts_ms));
  nonce[23]++;

  /* === Server-side decryption === */
  uint8_t srv_es[32], srv_ss[32], srv_nonce[24] = {0};
  uint8_t buf[96];
  HandshakeData *hs = DATA(p, HandshakeData);

  crypto_x25519(buf, server_sk, hs->e);
  memcpy(buf + 32, hs->e, 32);
  memcpy(buf + 64, server_pk, 32);
  crypto_blake2b(srv_es, 32, buf, 96);

  int rc1 = crypto_aead_unlock(hs->s, HEAD(p)->mac, srv_es, srv_nonce,
                                &HEAD(p)->type, 1, hs->s, 32);
  ASSERT_EQ(0, rc1);
  srv_nonce[23]++;

  ASSERT_MEM_EQ(client_pk, hs->s, 32);

  crypto_x25519(buf, server_sk, hs->s);
  memcpy(buf + 32, srv_es, 32);
  crypto_blake2b(srv_ss, 32, buf, 64);

  AdvertiseData *advd = DATA(p, AdvertiseData);
  int rc2 = crypto_aead_unlock((uint8_t *)&advd->ts_ms, advd->mac2, srv_ss,
                                srv_nonce, NULL, 0,
                                (uint8_t *)&advd->ts_ms, sizeof(advd->ts_ms));
  ASSERT_EQ(0, rc2);

  ASSERT_EQ(orig_ts, advd->ts_ms);
  PASS();
}

TEST connect_response_roundtrip(void) {
  /* Simulate server encrypting a CONNECT response and client decrypting it */
  uint8_t ss[32], nonce[24] = {0};
  uint8_t p[PACKET_MAX];

  rand_buf(32, ss);
  /* Skip nonces 0 and 1 as the protocol uses them for handshake layers */
  nonce[23] = 2;

  HEAD(p)->type = CONNECT;
  DATA(p, ConnectData)->addr = 0x0100007F; /* 127.0.0.1 in little-endian */
  DATA(p, ConnectData)->port = htons(8080);

  uint32_t orig_addr = DATA(p, ConnectData)->addr;
  uint16_t orig_port = DATA(p, ConnectData)->port;

  /* Server encrypts */
  crypto_aead_lock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce,
                   &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ConnectData));

  /* Client decrypts */
  int rc = crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce,
                               &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ConnectData));
  ASSERT_EQ(0, rc);
  ASSERT_EQ(orig_addr, DATA(p, ConnectData)->addr);
  ASSERT_EQ(orig_port, DATA(p, ConnectData)->port);
  PASS();
}

TEST error_response_roundtrip(void) {
  uint8_t ss[32], nonce[24] = {0};
  uint8_t p[PACKET_MAX];

  rand_buf(32, ss);
  nonce[23] = 2;

  HEAD(p)->type = ERROR;
  DATA(p, ErrorData)->code = ERROR_NOT_FOUND;

  crypto_aead_lock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce,
                   &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ErrorData));

  int rc = crypto_aead_unlock(DATA(p, uint8_t), HEAD(p)->mac, ss, nonce,
                               &HEAD(p)->type, 1, DATA(p, uint8_t), sizeof(ErrorData));
  ASSERT_EQ(0, rc);
  ASSERT_EQ(ERROR_NOT_FOUND, DATA(p, ErrorData)->code);
  PASS();
}

TEST wrong_ss_cannot_decrypt_attach(void) {
  uint8_t client_sk[32], client_pk[32];
  uint8_t server_sk[32], server_pk[32];
  uint8_t attacker_sk[32], attacker_pk[32];
  uint8_t target_pk[32];
  uint8_t e_pk[32], es[32], ss[32];
  uint8_t p[PACKET_MAX];
  uint8_t nonce[24] = {0};

  rand_buf(32, client_sk);
  crypto_x25519_public_key(client_pk, client_sk);
  rand_buf(32, server_sk);
  crypto_x25519_public_key(server_pk, server_sk);
  rand_buf(32, attacker_sk);
  crypto_x25519_public_key(attacker_pk, attacker_sk);
  rand_buf(32, target_pk);

  gen_keys(client_sk, client_pk, server_pk, e_pk, es, ss);

  HEAD(p)->type = ATTACH;
  memcpy(DATA(p, HandshakeData)->e, e_pk, 32);
  memcpy(DATA(p, HandshakeData)->s, client_pk, 32);
  memcpy(DATA(p, AttachData)->t, target_pk, 32);

  crypto_aead_lock(DATA(p, HandshakeData)->s, HEAD(p)->mac, es, nonce,
                   &HEAD(p)->type, 1, DATA(p, HandshakeData)->s, 32);
  nonce[23]++;
  crypto_aead_lock(DATA(p, AttachData)->t, DATA(p, AttachData)->mac2, ss, nonce,
                   NULL, 0, DATA(p, AttachData)->t, 32);

  /* Attacker tries to decrypt layer 1 with their own key */
  uint8_t atk_es[32], atk_nonce[24] = {0}, buf[96];
  HandshakeData *hs = DATA(p, HandshakeData);

  crypto_x25519(buf, attacker_sk, hs->e);
  memcpy(buf + 32, hs->e, 32);
  memcpy(buf + 64, attacker_pk, 32);
  crypto_blake2b(atk_es, 32, buf, 96);

  int rc = crypto_aead_unlock(hs->s, HEAD(p)->mac, atk_es, atk_nonce,
                               &HEAD(p)->type, 1, hs->s, 32);
  ASSERT(rc != 0);
  PASS();
}

SUITE(protocol_suite) {
  RUN_TEST(attach_packet_roundtrip);
  RUN_TEST(advertise_packet_roundtrip);
  RUN_TEST(connect_response_roundtrip);
  RUN_TEST(error_response_roundtrip);
  RUN_TEST(wrong_ss_cannot_decrypt_attach);
}

/* ================================================================
 * SUITE: X25519 key generation (as used in main.c keygen)
 * ================================================================ */

TEST x25519_pubkey_deterministic(void) {
  uint8_t sk[32], pk1[32], pk2[32];
  rand_buf(32, sk);
  crypto_x25519_public_key(pk1, sk);
  crypto_x25519_public_key(pk2, sk);
  ASSERT_MEM_EQ(pk1, pk2, 32);
  PASS();
}

TEST x25519_different_sk_different_pk(void) {
  uint8_t sk1[32], sk2[32], pk1[32], pk2[32];
  rand_buf(32, sk1);
  rand_buf(32, sk2);
  crypto_x25519_public_key(pk1, sk1);
  crypto_x25519_public_key(pk2, sk2);
  ASSERT(memcmp(pk1, pk2, 32) != 0);
  PASS();
}

TEST x25519_dh_agreement(void) {
  uint8_t sk_a[32], pk_a[32], sk_b[32], pk_b[32];
  uint8_t shared_ab[32], shared_ba[32];

  rand_buf(32, sk_a);
  crypto_x25519_public_key(pk_a, sk_a);
  rand_buf(32, sk_b);
  crypto_x25519_public_key(pk_b, sk_b);

  crypto_x25519(shared_ab, sk_a, pk_b);
  crypto_x25519(shared_ba, sk_b, pk_a);

  ASSERT_MEM_EQ(shared_ab, shared_ba, 32);
  PASS();
}

SUITE(x25519_suite) {
  RUN_TEST(x25519_pubkey_deterministic);
  RUN_TEST(x25519_different_sk_different_pk);
  RUN_TEST(x25519_dh_agreement);
}

/* ================================================================
 * SUITE: Packet layout - field offset verification
 * ================================================================ */

TEST handshake_field_offsets(void) {
  uint8_t p[PACKET_MAX] = {0};
  HandshakeData *hs = DATA(p, HandshakeData);

  /* e is at offset 0 within HandshakeData */
  ASSERT_EQ((void *)hs, (void *)hs->e);
  /* s is at offset 32 */
  ASSERT_EQ((void *)((uint8_t *)hs + 32), (void *)hs->s);
  PASS();
}

TEST attach_field_offsets(void) {
  uint8_t p[PACKET_MAX] = {0};
  AttachData *ad = DATA(p, AttachData);

  /* hs at offset 0 */
  ASSERT_EQ((void *)ad, (void *)&ad->hs);
  /* t at offset 64 */
  ASSERT_EQ((void *)((uint8_t *)ad + 64), (void *)ad->t);
  /* mac2 at offset 96 */
  ASSERT_EQ((void *)((uint8_t *)ad + 96), (void *)ad->mac2);
  PASS();
}

TEST advertise_field_offsets(void) {
  uint8_t p[PACKET_MAX] = {0};
  AdvertiseData *ad = DATA(p, AdvertiseData);

  ASSERT_EQ((void *)ad, (void *)&ad->hs);
  /* ts_ms at offset 64 */
  ASSERT_EQ((void *)((uint8_t *)ad + 64), (void *)&ad->ts_ms);
  /* mac2 at offset 72 */
  ASSERT_EQ((void *)((uint8_t *)ad + 72), (void *)ad->mac2);
  PASS();
}

TEST connect_field_offsets(void) {
  ConnectData cd;
  ASSERT_EQ((void *)&cd, (void *)&cd.addr);
  ASSERT_EQ((void *)((uint8_t *)&cd + 4), (void *)&cd.port);
  PASS();
}

SUITE(layout_suite) {
  RUN_TEST(handshake_field_offsets);
  RUN_TEST(attach_field_offsets);
  RUN_TEST(advertise_field_offsets);
  RUN_TEST(connect_field_offsets);
}

/* ================================================================
 * Main
 * ================================================================ */

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
  GREATEST_MAIN_BEGIN();

  RUN_SUITE(packet_suite);
  RUN_SUITE(key2hex_suite);
  RUN_SUITE(rand_buf_suite);
  RUN_SUITE(read_key_suite);
  RUN_SUITE(ts2ms_suite);
  RUN_SUITE(gen_keys_suite);
  RUN_SUITE(aead_suite);
  RUN_SUITE(protocol_suite);
  RUN_SUITE(x25519_suite);
  RUN_SUITE(layout_suite);

  GREATEST_MAIN_END();
}
