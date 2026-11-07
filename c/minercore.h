/*
 * minercore - portable Stratum v1 Bitcoin mining core (no OS dependencies).
 *
 * Built unchanged for the classic Mac app (Retro68, 68k) and for the host
 * test tools in c/host/.  It is a direct port of reference/stratum_reference.py
 * and is checked against it by c/host/test_core.c.
 */
#ifndef MINERCORE_H
#define MINERCORE_H

#include <stdint.h>

#define MC_MAX_CB      1200   /* hex chars kept for each of coinb1 / coinb2 */
#define MC_MAX_BRANCH  24
#define MC_MAX_LINE    8192   /* longest Stratum line we buffer             */

/* ---- hashing --------------------------------------------------------- */
typedef struct { uint32_t h[8]; } mc_sha_state;

void mc_sha256_init(mc_sha_state *s);
void mc_sha256_block(mc_sha_state *s, const uint8_t *blk64);
void mc_sha256(const uint8_t *data, uint32_t len, uint8_t out[32]);
void mc_sha256d(const uint8_t *data, uint32_t len, uint8_t out[32]);

/* ---- helpers ---------------------------------------------------------- */
int  mc_hex_decode(const char *hex, uint8_t *out, int maxbytes); /* -> bytes */
void mc_hex_encode(const uint8_t *in, int n, char *out);          /* NUL-terminated */

/* Share target = DIFF1 * den / num  (pool difficulty = num/den), 32 bytes BE. */
void mc_target_from_diff(uint32_t num, uint32_t den, uint8_t target[32]);
/* hash (32 bytes, INTERNAL little-endian order as produced by sha256d) <= target ? */
int  mc_meets_target(const uint8_t hash_internal[32], const uint8_t target[32]);
/* convenience: integer difficulty */
int  mc_meets_difficulty(const uint8_t hash_internal[32], uint32_t diff);

/* ---- Stratum session -------------------------------------------------- */
typedef void (*mc_send_fn)(void *user, const char *line);  /* line has no '\n' */

typedef struct {
    /* outbound plumbing */
    mc_send_fn send;
    void      *user;

    /* credentials: authorize name is "wallet.worker" */
    char username[128];
    char password[64];

    /* session state */
    int  subscribed, authorized, have_job;
    int  next_id;
    char extranonce1[40];
    int  en2_size;
    uint32_t en2_counter;        /* extranonce2 value, big-endian in hex   */
    char en2_hex[40];
    uint32_t difficulty;         /* pool difficulty, rounded up (display)  */
    uint8_t  target[32];         /* exact share target, big-endian         */

    /* current job */
    char job_id[80];
    char prevhash[72];
    char version[16], nbits[16], ntime[16];
    char coinb1[MC_MAX_CB + 1], coinb2[MC_MAX_CB + 1];
    uint8_t branch[MC_MAX_BRANCH][32];
    int  nbranch;
    int  clean_jobs;

    /* header work area */
    uint8_t header[80];
    mc_sha_state mid;            /* midstate after the first 64 header bytes */
    uint32_t nonce;
    uint32_t job_serial;         /* bumps on every new job                  */

    /* stats */
    uint32_t hashes, shares_found, shares_ok, shares_bad;
    char last_error[96];
} mc_session;

void mc_session_init(mc_session *s, mc_send_fn send, void *user,
                     const char *wallet, const char *worker, const char *password);

/* Send mining.subscribe (call right after the TCP connection is up). */
void mc_start(mc_session *s);

/* Feed one complete Stratum line (no trailing newline). */
void mc_handle_line(mc_session *s, const char *line);

/* Rebuild coinbase/merkle/header for the current job + extranonce2. */
void mc_prepare_job(mc_session *s);

/* Try `count` nonces.  Submits any share found (via s->send).  Returns the
 * number of shares submitted during this call.  No-op until a job exists
 * and the worker is authorized. */
int  mc_mine(mc_session *s, uint32_t count);

/* Hash the real genesis header; returns 1 if SHA-256d + difficulty are right. */
int  mc_selftest(void);

#endif
