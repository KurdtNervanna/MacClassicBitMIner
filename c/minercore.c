/* minercore.c - see minercore.h.  Port of reference/stratum_reference.py. */
#include "minercore.h"
#include <string.h>
#include <stdio.h>

/* ======================================================================
 *  SHA-256
 * ====================================================================== */
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

void mc_sha256_init(mc_sha_state *s)
{
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
}

/* Byte-wise big-endian load: correct on any CPU and with any alignment. */
static uint32_t ld32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void compress(mc_sha_state *s, const uint32_t *w16)
{
    uint32_t W[64], a,b,c,d,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++) W[i] = w16[i];
    for (i = 16; i < 64; i++) {
        uint32_t x = W[i-15], y = W[i-2];
        uint32_t s0 = ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3);
        uint32_t s1 = ROTR(y,17) ^ ROTR(y,19) ^ (y >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    a=s->h[0]; b=s->h[1]; c=s->h[2]; d=s->h[3];
    e=s->h[4]; f=s->h[5]; g=s->h[6]; h=s->h[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)) + ((e & f) ^ (~e & g)) + K[i] + W[i];
        t2 = (ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)) + ((a & b) ^ (a & c) ^ (b & c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

void mc_sha256_block(mc_sha_state *s, const uint8_t *blk)
{
    uint32_t w[16]; int i;
    for (i = 0; i < 16; i++) w[i] = ld32(blk + i * 4);
    compress(s, w);
}

static void st_out(const mc_sha_state *s, uint8_t out[32])
{
    int i;
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(s->h[i] >> 24);
        out[i*4+1] = (uint8_t)(s->h[i] >> 16);
        out[i*4+2] = (uint8_t)(s->h[i] >> 8);
        out[i*4+3] = (uint8_t)(s->h[i]);
    }
}

void mc_sha256(const uint8_t *data, uint32_t len, uint8_t out[32])
{
    mc_sha_state s; uint8_t pad[128]; uint32_t full = len / 64, rem = len % 64, i, off;
    uint32_t bits_hi = len >> 29, bits_lo = len << 3;
    mc_sha256_init(&s);
    for (i = 0; i < full; i++) mc_sha256_block(&s, data + i * 64);
    memset(pad, 0, sizeof pad);
    if (rem) memcpy(pad, data + full * 64, rem);
    pad[rem] = 0x80;
    off = (rem <= 55) ? 56 : 120;
    pad[off]   = (uint8_t)(bits_hi >> 24); pad[off+1] = (uint8_t)(bits_hi >> 16);
    pad[off+2] = (uint8_t)(bits_hi >> 8);  pad[off+3] = (uint8_t)bits_hi;
    pad[off+4] = (uint8_t)(bits_lo >> 24); pad[off+5] = (uint8_t)(bits_lo >> 16);
    pad[off+6] = (uint8_t)(bits_lo >> 8);  pad[off+7] = (uint8_t)bits_lo;
    mc_sha256_block(&s, pad);
    if (rem > 55) mc_sha256_block(&s, pad + 64);
    st_out(&s, out);
}

void mc_sha256d(const uint8_t *data, uint32_t len, uint8_t out[32])
{
    uint8_t mid[32];
    mc_sha256(data, len, mid);
    mc_sha256(mid, 32, out);
}

/* ======================================================================
 *  hex helpers
 * ====================================================================== */
static int hv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int mc_hex_decode(const char *hex, uint8_t *out, int maxbytes)
{
    int n = 0;
    while (hex[0] && hex[1] && n < maxbytes) {
        int a = hv(hex[0]), b = hv(hex[1]);
        if (a < 0 || b < 0) break;
        out[n++] = (uint8_t)(a * 16 + b);
        hex += 2;
    }
    return n;
}

void mc_hex_encode(const uint8_t *in, int n, char *out)
{
    static const char d[] = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) { out[i*2] = d[in[i] >> 4]; out[i*2+1] = d[in[i] & 15]; }
    out[n*2] = 0;
}

/* ======================================================================
 *  difficulty
 * ====================================================================== */
void mc_target_from_diff(uint32_t num, uint32_t den, uint8_t target[32])
{
    uint8_t prod[36]; uint64_t carry = 0, rem = 0; int i;
    if (num < 1) num = 1;
    if (den < 1) den = 1;
    /* prod = DIFF1 * den  (DIFF1 = 0x00000000FFFF0000...0, 32 bytes BE) */
    for (i = 31; i >= 0; i--) {
        uint64_t t = (uint64_t)((i == 4 || i == 5) ? 0xFF : 0x00) * den + carry;
        prod[i + 4] = (uint8_t)t; carry = t >> 8;
    }
    for (i = 3; i >= 0; i--) { prod[i] = (uint8_t)carry; carry >>= 8; }
    /* target = prod / num  (36 -> 32 bytes; a quotient wider than 256 bits
       can only happen for difficulty < 1/65536 and is clamped to all-FF) */
    for (i = 0; i < 36; i++) {
        uint64_t cur = (rem << 8) | prod[i];
        uint64_t q = cur / num;
        rem = cur % num;
        if (i < 4) { if (q) { memset(target, 0xFF, 32); return; } }
        else target[i - 4] = (uint8_t)q;
    }
}

int mc_meets_target(const uint8_t hash_internal[32], const uint8_t target[32])
{
    int i;
    /* hash is little-endian: compare from its last byte (most significant) */
    for (i = 0; i < 32; i++) {
        uint8_t hb = hash_internal[31 - i];
        if (hb < target[i]) return 1;
        if (hb > target[i]) return 0;
    }
    return 1;
}

int mc_meets_difficulty(const uint8_t hash_internal[32], uint32_t diff)
{
    uint8_t t[32];
    mc_target_from_diff(diff, 1, t);
    return mc_meets_target(hash_internal, t);
}

/* ======================================================================
 *  tiny JSON scanner (enough for Stratum v1)
 * ====================================================================== */
static const char *ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

/* pointer to the value following  "key":  (first occurrence), or NULL */
static const char *find_key(const char *line, const char *key)
{
    char pat[40]; const char *p;
    snprintf(pat, sizeof pat, "\"%s\"", key);
    p = strstr(line, pat);
    if (!p) return NULL;
    p = ws(p + strlen(pat));
    if (*p != ':') return NULL;
    return ws(p + 1);
}

/* p at opening quote; copies (unescaped) into out; returns past closing quote */
static const char *read_str(const char *p, char *out, int max)
{
    int n = 0;
    if (*p != '"') { if (max) out[0] = 0; return p; }
    p++;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) c = *p++;
        if (n < max - 1) out[n++] = c;
    }
    if (*p == '"') p++;
    out[n] = 0;
    return p;
}

static const char *skip_value(const char *p)
{
    p = ws(p);
    if (*p == '"') {
        p++;
        while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
        return *p ? p + 1 : p;
    }
    if (*p == '[' || *p == '{') {
        int depth = 0;
        for (; *p; p++) {
            if (*p == '"') { p = skip_value(p) - 1; continue; }
            if (*p == '[' || *p == '{') depth++;
            else if (*p == ']' || *p == '}') { if (--depth == 0) return p + 1; }
        }
        return p;
    }
    while (*p && *p != ',' && *p != ']' && *p != '}') p++;
    return p;
}

static const char *next_elem(const char *p)      /* after a value: step over ',' */
{
    p = ws(p);
    if (*p == ',') p = ws(p + 1);
    return p;
}

static long read_int(const char *p)
{
    long v = 0; int neg = 0;
    p = ws(p);
    if (*p == '-') { neg = 1; p++; }
    while (*p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
    return neg ? -v : v;
}

/* Parse a JSON difficulty (1, 16384, 0.001, 2.5e-3) into num/den (den<=1e6)
 * and a rounded-up integer for display. */
static void read_diff(const char *p, uint32_t *num, uint32_t *den, uint32_t *ceil_out)
{
    uint32_t ip = 0, fp = 0, d = 1; int digits = 0, exp = 0, expneg = 0, frac = 0;
    p = ws(p);
    while (*p >= '0' && *p <= '9') { if (ip < 0x0FFFFFFF) ip = ip * 10 + (uint32_t)(*p - '0'); p++; }
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            if (digits < 6) { fp = fp * 10 + (uint32_t)(*p - '0'); d *= 10; digits++; }
            if (*p != '0') frac = 1;
            p++;
        }
    }
    if (*p == 'e' || *p == 'E') {              /* rare; handle by scaling */
        p++;
        if (*p == '-') { expneg = 1; p++; } else if (*p == '+') p++;
        while (*p >= '0' && *p <= '9') exp = exp * 10 + (*p++ - '0');
    }
    if (ip >= 4096) { fp = 0; d = 1; }         /* big difficulties are integers */
    *num = ip * d + fp; *den = d;
    if (exp) {
        while (exp-- > 0) {
            if (expneg) { if (*den < 100000) *den *= 10; else *num /= 10; }
            else        { if (*num < 400000000u) *num *= 10; }
        }
    }
    if (*num < 1) *num = 1;
    *ceil_out = (*num + *den - 1) / *den;
    (void)frac;
}

/* ======================================================================
 *  Stratum session
 * ====================================================================== */
static void say(mc_session *s, const char *line)
{
    if (s->send) s->send(s->user, line);
}

static void json_escape(const char *in, char *out, int max)
{
    int n = 0;
    for (; *in && n < max - 2; in++) {
        if (*in == '"' || *in == '\\') out[n++] = '\\';
        out[n++] = *in;
    }
    out[n] = 0;
}

void mc_session_init(mc_session *s, mc_send_fn send, void *user,
                     const char *wallet, const char *worker, const char *password)
{
    memset(s, 0, sizeof *s);
    s->send = send; s->user = user;
    /* pools (ckpool etc.) want  <btc address>.<worker> */
    if (worker && worker[0]) snprintf(s->username, sizeof s->username, "%s.%s", wallet, worker);
    else snprintf(s->username, sizeof s->username, "%s", wallet);
    snprintf(s->password, sizeof s->password, "%s", (password && password[0]) ? password : "x");
    s->next_id = 3;
    s->difficulty = 1;
    mc_target_from_diff(1, 1, s->target);
    s->en2_size = 4;
}

void mc_start(mc_session *s)
{
    say(s, "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"MacClassicBitMiner/2.0\"]}");
    /* ask for the easiest share difficulty; pools that honour it (ckpool) lower
       our target, others ignore it.  id 100 is reserved for this reply. */
    say(s, "{\"id\":100,\"method\":\"mining.suggest_difficulty\",\"params\":[1]}");
}

static void send_authorize(mc_session *s)
{
    char u[256], p[128], line[512];
    json_escape(s->username, u, sizeof u);
    json_escape(s->password, p, sizeof p);
    snprintf(line, sizeof line,
             "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}", u, p);
    say(s, line);
}

static void build_en2(mc_session *s)
{
    uint8_t b[16]; int n = s->en2_size, i;
    if (n < 1) n = 1;
    if (n > 16) n = 16;
    memset(b, 0, sizeof b);
    for (i = 0; i < 4 && i < n; i++)
        b[n - 1 - i] = (uint8_t)(s->en2_counter >> (8 * i));
    mc_hex_encode(b, n, s->en2_hex);
}

void mc_prepare_job(mc_session *s)
{
    static uint8_t cb[(MC_MAX_CB * 2 + 100) / 2 + 16];
    uint8_t root[32], cat[64], tmp[32]; int n = 0, k, w, b;
    static char hex[MC_MAX_CB * 2 + 100];   /* static: classic Mac stacks are tiny */

    build_en2(s);
    snprintf(hex, sizeof hex, "%s%s%s%s", s->coinb1, s->extranonce1, s->en2_hex, s->coinb2);
    n = mc_hex_decode(hex, cb, (int)sizeof cb);
    mc_sha256d(cb, (uint32_t)n, root);
    for (k = 0; k < s->nbranch; k++) {
        memcpy(cat, root, 32); memcpy(cat + 32, s->branch[k], 32);
        mc_sha256d(cat, 64, root);
    }
    /* version | prevhash | merkle | ntime | nbits | nonce */
    mc_hex_decode(s->version, tmp, 4);
    for (b = 0; b < 4; b++) s->header[b] = tmp[3 - b];
    mc_hex_decode(s->prevhash, tmp, 32);
    for (w = 0; w < 8; w++) for (b = 0; b < 4; b++) s->header[4 + w*4 + b] = tmp[w*4 + (3 - b)];
    memcpy(s->header + 36, root, 32);
    mc_hex_decode(s->ntime, tmp, 4);
    for (b = 0; b < 4; b++) s->header[68 + b] = tmp[3 - b];
    mc_hex_decode(s->nbits, tmp, 4);
    for (b = 0; b < 4; b++) s->header[72 + b] = tmp[3 - b];
    memset(s->header + 76, 0, 4);

    mc_sha256_init(&s->mid);
    mc_sha256_block(&s->mid, s->header);       /* midstate: first 64 bytes never change */
    s->nonce = 0;
    s->job_serial++;
}

static void on_subscribe(mc_session *s, const char *line)
{
    const char *p = find_key(line, "result");
    long sz;
    if (!p || *p != '[') return;
    p = ws(p + 1);
    p = skip_value(p);                          /* subscription tuples */
    p = next_elem(p);
    p = read_str(p, s->extranonce1, sizeof s->extranonce1);
    p = next_elem(p);
    sz = read_int(p);
    s->en2_size = (sz >= 1 && sz <= 16) ? (int)sz : 4;
    s->subscribed = 1;
    send_authorize(s);
}

static void on_notify(mc_session *s, const char *line)
{
    const char *p = find_key(line, "params");
    static char tmp[MC_MAX_CB + 1];
    if (!p || *p != '[') return;
    p = ws(p + 1);
    p = read_str(p, s->job_id, sizeof s->job_id);          p = next_elem(p);
    p = read_str(p, s->prevhash, sizeof s->prevhash);      p = next_elem(p);
    p = read_str(p, s->coinb1, sizeof s->coinb1);          p = next_elem(p);
    p = read_str(p, s->coinb2, sizeof s->coinb2);          p = next_elem(p);
    s->nbranch = 0;
    if (*p == '[') {
        p = ws(p + 1);
        while (*p && *p != ']') {
            p = read_str(p, tmp, 80);
            if (s->nbranch < MC_MAX_BRANCH)
                mc_hex_decode(tmp, s->branch[s->nbranch++], 32);
            p = next_elem(p);
        }
        if (*p == ']') p++;
    }
    p = next_elem(p);
    p = read_str(p, s->version, sizeof s->version);        p = next_elem(p);
    p = read_str(p, s->nbits, sizeof s->nbits);            p = next_elem(p);
    p = read_str(p, s->ntime, sizeof s->ntime);            p = next_elem(p);
    s->clean_jobs = (strncmp(p, "true", 4) == 0);
    s->have_job = 1;
    if (s->subscribed) { s->en2_counter = 0; mc_prepare_job(s); }
}

static void on_result(mc_session *s, long id, const char *line)
{
    const char *r = find_key(line, "result");
    int ok = (r && strncmp(r, "true", 4) == 0);
    if (id == 1) { on_subscribe(s, line); return; }
    if (id == 100) return;                       /* suggest_difficulty reply */
    if (id == 2) {
        if (ok) { s->authorized = 1; s->last_error[0] = 0; }
        else snprintf(s->last_error, sizeof s->last_error, "authorize rejected");
        return;
    }
    if (ok) s->shares_ok++;
    else {
        const char *e = find_key(line, "error");
        s->shares_bad++;
        if (e && *e == '[') {
            char m[64]; const char *q = ws(e + 1);
            q = skip_value(q); q = next_elem(q);          /* skip error code */
            read_str(q, m, sizeof m);
            snprintf(s->last_error, sizeof s->last_error, "share rejected: %s", m);
        }
    }
}

void mc_handle_line(mc_session *s, const char *line)
{
    const char *m = find_key(line, "method");
    if (m && *m == '"') {
        char name[48];
        read_str(m, name, sizeof name);
        if (!strcmp(name, "mining.notify")) on_notify(s, line);
        else if (!strcmp(name, "mining.set_difficulty")) {
            const char *p = find_key(line, "params");
            if (p && *p == '[') {
                uint32_t n, d;
                read_diff(p + 1, &n, &d, &s->difficulty);
                mc_target_from_diff(n, d, s->target);
            }
        } else if (!strcmp(name, "mining.set_extranonce")) {
            const char *p = find_key(line, "params");
            if (p && *p == '[') {
                p = ws(p + 1);
                p = read_str(p, s->extranonce1, sizeof s->extranonce1);
                p = next_elem(p);
                s->en2_size = (int)read_int(p);
                if (s->en2_size < 1 || s->en2_size > 16) s->en2_size = 4;
            }
        }
        return;
    }
    {
        const char *i = find_key(line, "id");
        if (i && ((*i >= '0' && *i <= '9') || *i == '-')) on_result(s, read_int(i), line);
    }
}

/* Double-SHA256 of header (nonce set) using the cached midstate. */
static void hash_nonce(const mc_session *s, uint32_t nonce, uint8_t out[32])
{
    mc_sha_state st = s->mid;
    uint32_t w[16]; int i;
    uint8_t first[32];
    /* second block of the 80-byte header: bytes 64..79, 0x80, zeros, len=640 */
    w[0] = ld32(s->header + 64); w[1] = ld32(s->header + 68); w[2] = ld32(s->header + 72);
    w[3] = ((nonce & 0xFF) << 24) | ((nonce & 0xFF00) << 8)
         | ((nonce >> 8) & 0xFF00) | (nonce >> 24);              /* nonce is LE in header */
    w[4] = 0x80000000u;
    for (i = 5; i < 15; i++) w[i] = 0;
    w[15] = 640;
    compress(&st, w);
    st_out(&st, first);
    /* second SHA-256 over the 32-byte digest */
    {
        mc_sha_state s2; mc_sha256_init(&s2);
        for (i = 0; i < 8; i++) w[i] = ld32(first + i * 4);
        w[8] = 0x80000000u;
        for (i = 9; i < 15; i++) w[i] = 0;
        w[15] = 256;
        compress(&s2, w);
        st_out(&s2, out);
    }
}

static void submit(mc_session *s, uint32_t nonce)
{
    char u[256], line[640];
    json_escape(s->username, u, sizeof u);
    snprintf(line, sizeof line,
        "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%08lx\"]}",
        s->next_id++, u, s->job_id, s->en2_hex, s->ntime, (unsigned long)nonce);
    say(s, line);
    s->shares_found++;
}

int mc_mine(mc_session *s, uint32_t count)
{
    int found = 0; uint8_t h[32];
    if (!s->have_job || !s->authorized || !s->subscribed) return 0;
    while (count--) {
        hash_nonce(s, s->nonce, h);
        s->hashes++;
        /* cheap early-out on the most significant byte before the full compare */
        if (h[31] <= s->target[0] && mc_meets_target(h, s->target)) {
            submit(s, s->nonce); found++;
        }
        if (++s->nonce == 0) {               /* nonce space exhausted: new extranonce2 */
            s->en2_counter++;
            mc_prepare_job(s);
        }
    }
    return found;
}

/* ======================================================================
 *  self-test: the real Bitcoin genesis block header
 * ====================================================================== */
int mc_selftest(void)
{
    static const char hdr[] =
        "0100000000000000000000000000000000000000000000000000000000000000"
        "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
        "4b1e5e4a29ab5f49ffff001d1dac2b7c";
    static const char want[] =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    uint8_t b[80], h[32], be[32], h2[32]; char hex[65]; int i;
    static mc_session s;
    if (mc_hex_decode(hdr, b, 80) != 80) return 0;
    mc_sha256d(b, 80, h);
    for (i = 0; i < 32; i++) be[i] = h[31 - i];
    mc_hex_encode(be, 32, hex);
    if (strcmp(hex, want) != 0) return 0;
    /* the midstate/nonce fast path must agree with the plain path */
    memset(&s, 0, sizeof s);
    memcpy(s.header, b, 80);
    mc_sha256_init(&s.mid); mc_sha256_block(&s.mid, b);
    hash_nonce(&s, (uint32_t)(b[76] | (b[77] << 8) | (b[78] << 16) | ((uint32_t)b[79] << 24)), h2);
    if (memcmp(h, h2, 32) != 0) return 0;
    /* genesis hash has 32 leading zero bits => diff 1 passes, diff 2^24 fails */
    if (!mc_meets_difficulty(h, 1)) return 0;
    if (mc_meets_difficulty(h, 16777216u)) return 0;
    return 1;
}
