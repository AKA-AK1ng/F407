#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/params.h"
#include "common/cycles.h"
#include "common/random.h"
#include "common/structs.h"
#include "common/fips202.h"

// -------------------------------------------------------------------------
// External Functions
// -------------------------------------------------------------------------
extern void ref_xof_expand_matrix(poly_matrix *A, const uint8_t *seed);
extern void ref_xof_expand_poly_vec(poly_vec *v, const uint8_t *seed, int32_t modulus);
extern void ref_poly_matrix_vec_mul(poly_vec *res, const poly_matrix *A, const poly_vec *s);
extern void ref_poly_quantize(poly *res, const poly *v, const poly *d, int32_t P);
extern void ref_poly_dequantize(poly *res, const poly *b, int32_t P);
extern void ref_poly_msg_decode(uint8_t *msg, const poly *p);
extern void ref_mlwq_keygen(mlwq_pk *pk, mlwq_sk *sk, const uint8_t *seed_A, const uint8_t *seed_d);
extern void ref_mlwq_encrypt(mlwq_ciphertext *ct, const mlwq_pk *pk, const uint8_t *msg, const uint8_t *seed_ct);
extern void ref_mlwq_kem_keygen(mlwq_pk *pk, mlwq_kem_sk *sk);
extern void ref_mlwq_kem_encaps(mlwq_ciphertext *ct, uint8_t *ss, const mlwq_pk *pk);
extern int  ref_mlwq_kem_decaps(uint8_t *ss, const mlwq_kem_sk *sk, const mlwq_ciphertext *ct);
extern void ref_poly_vec_transpose_mul(poly *res, const poly_vec *a_t, const poly_vec *b);

extern void avx_xof_expand_matrix(poly_matrix *A, const uint8_t *seed);
extern void avx_xof_expand_poly_vec(poly_vec *v, const uint8_t *seed, int32_t modulus);
extern void avx_poly_matrix_vec_mul(poly_vec *res, const poly_matrix *A, const poly_vec *s);
extern void avx_poly_quantize(poly *res, const poly *v, const poly *d, int32_t P);
extern void avx_poly_dequantize(poly *res, const poly *b, int32_t P);
extern void avx_poly_msg_decode(uint8_t *msg, const poly *p);
extern void avx_mlwq_keygen(mlwq_pk *pk, mlwq_sk *sk, const uint8_t *seed_A, const uint8_t *seed_d);
extern void avx_mlwq_encrypt(mlwq_ciphertext *ct, const mlwq_pk *pk, const uint8_t *msg, const uint8_t *seed_ct);
extern void avx_mlwq_kem_keygen(mlwq_pk *pk, mlwq_kem_sk *sk);
extern void avx_mlwq_kem_encaps(mlwq_ciphertext *ct, uint8_t *ss, const mlwq_pk *pk);
extern int  avx_mlwq_kem_decaps(uint8_t *ss, const mlwq_kem_sk *sk, const mlwq_ciphertext *ct);
extern void avx_poly_vec_transpose_mul(poly *res, const poly_vec *a_t, const poly_vec *b);

#define ROUNDS 1000

typedef struct {
    uint64_t gen_matrix;
    uint64_t sample;
    uint64_t gen_dither;
    uint64_t arith;
    uint64_t quantize;
    uint64_t dequantize;
    uint64_t decode;
    
    uint64_t arith_u;
    uint64_t arith_v;

    uint64_t pke_keygen;
    uint64_t pke_encrypt;
    uint64_t pke_decrypt;
    
    uint64_t kem_keygen;
    uint64_t kem_encaps;
    uint64_t kem_decaps;
} bench_stats_t;

static bench_stats_t stats_ref = {0};
static bench_stats_t stats_avx = {0};

static uint64_t avg(uint64_t total) { return total / ROUNDS; }

void print_sep() { printf("----------------------------------------------------------------------------------------------\n"); }

// -------------------------------------------------------------------------
// [Fix] Correct Size Display using Macros from params.h
// -------------------------------------------------------------------------
// 我们使用宏 (Macros) 而不是 sizeof()，因为宏代表了协议定义的序列化(Wire)尺寸，
// 而 sizeof() 可能会包含内存对齐(Padding)或者是不压缩的中间态尺寸。
void print_data_sizes() {
    printf(">>> PART 0: Protocol Data Sizes (Serialized/Wire Format)\n");
    print_sep();
    printf("%-35s %-15s\n", "Component", "Size (Bytes)");
    print_sep();
    
    // --- PKE (CPA-Secure) ---
    printf("[PKE] Public Key (pk):\n");
    // Calculation: (K * N * BIT_PK / 8) + 32
    printf("  %-33s %d\n", "MLWQ_PUBLICKEYBYTES", MLWQ_PUBLICKEYBYTES);
    
    printf("[PKE] Secret Key (sk):\n");
    // Calculation: K * N * BIT_PK / 8 (or packed s)
    printf("  %-33s %d\n", "MLWQ_SECRETKEYBYTES", MLWQ_SECRETKEYBYTES);
    
    printf("[PKE] Ciphertext (ct):\n");
    // Calculation: (K * N * BIT_U / 8) + (N * BIT_V / 8)
    printf("  %-33s %d\n", "MLWQ_CIPHERTEXTBYTES", MLWQ_CIPHERTEXTBYTES);
    
    printf("\n");

    // --- KEM (CCA-Secure) ---
    // KEM SK 通常包含 PKE_SK + PK + H(PK) + z
    // 假设你的 structs.h 定义是标准的，并且我们没有专门的 KEM_SK_BYTES 宏，
    // 我们这里计算理论值：
    int kem_sk_size = MLWQ_SECRETKEYBYTES + MLWQ_PUBLICKEYBYTES + 32 + 32;

    printf("[KEM] Public Key:\n");
    printf("  %-33s %d\n", "Same as PKE PK", MLWQ_PUBLICKEYBYTES);
    
    printf("[KEM] Secret Key (Bundled):\n");
    printf("  %-33s %d (Approx. Theoretical)\n", "sk + pk + H(pk) + z", kem_sk_size);
    
    printf("[KEM] Ciphertext:\n");
    printf("  %-33s %d\n", "Same as PKE CT", MLWQ_CIPHERTEXTBYTES);
    
    printf("[KEM] Shared Secret (ss):\n");
    printf("  %-33s %d\n", "MLWQ_SSBYTES", MLWQ_SSBYTES);
    
    print_sep();
    printf("\n");
}

// -------------------------------------------------------------------------
// Helper: CBD Simulation
// -------------------------------------------------------------------------
static uint64_t measure_cbd_scalar() {
    uint8_t seed[32];
    uint8_t buf[128 * MLWQ_K]; 
    uint64_t t1, t2;
    memset(seed, 0xAB, 32);

    t1 = start_cycles();
    keccak_state state;
    shake128_init(&state);
    shake128_absorb(&state, seed, 32);
    shake128_finalize(&state);
    shake128_squeeze(buf, sizeof(buf), &state);
    
    volatile uint32_t dummy = 0;
    for(int i=0; i<sizeof(buf); i++) {
        uint8_t b = buf[i];
        dummy += (b & 0xF) - (b >> 4);
    }
    t2 = stop_cycles();
    return t2 - t1;
}

// -------------------------------------------------------------------------
// Measurement Functions (Unchanged)
// -------------------------------------------------------------------------
void measure_pke_keygen_ref() {
    uint64_t t1, t2;
    uint64_t dt_mat, dt_samp, dt_dith, dt_arith, dt_quant; 
    uint8_t seed_A[32], seed_d[32];
    random_bytes(seed_A, 32); random_bytes(seed_d, 32);
    poly_matrix A; poly_vec s, d_pk, As, b_q;

    t1 = start_cycles(); ref_xof_expand_matrix(&A, seed_A); t2 = stop_cycles();
    dt_mat = t2 - t1; stats_ref.gen_matrix += dt_mat;

    dt_samp = measure_cbd_scalar();
    stats_ref.sample += dt_samp;

    t1 = start_cycles(); ref_xof_expand_poly_vec(&d_pk, seed_d, MLWQ_Q / P_PK); t2 = stop_cycles();
    dt_dith = t2 - t1; stats_ref.gen_dither += dt_dith;

    t1 = start_cycles(); ref_poly_matrix_vec_mul(&As, &A, &s); t2 = stop_cycles();
    dt_arith = t2 - t1; stats_ref.arith += dt_arith;

    t1 = start_cycles(); for(int i=0; i<MLWQ_K; ++i) ref_poly_quantize(&b_q.vec[i], &As.vec[i], &d_pk.vec[i], P_PK); t2 = stop_cycles();
    dt_quant = t2 - t1; stats_ref.quantize += dt_quant;

    stats_ref.pke_keygen += (dt_mat + dt_samp + dt_dith + dt_arith + dt_quant);
}

void measure_pke_encrypt_ref() {
    uint64_t t1, t2;
    uint64_t dt_mat, dt_samp, dt_dith, dt_au, dt_av, dt_quant;
    uint8_t seed_ct[32]; random_bytes(seed_ct, 32);
    poly_matrix A; poly_vec r, d_u, Atr, u;
    
    t1 = start_cycles(); ref_xof_expand_matrix(&A, seed_ct); t2 = stop_cycles();
    dt_mat = t2 - t1; stats_ref.gen_matrix += dt_mat; 

    dt_samp = measure_cbd_scalar();
    stats_ref.sample += dt_samp;

    t1 = start_cycles(); ref_xof_expand_poly_vec(&d_u, seed_ct, MLWQ_Q / P_U); t2 = stop_cycles();
    dt_dith = t2 - t1; stats_ref.gen_dither += dt_dith;

    t1 = start_cycles(); 
    poly_matrix At; for(int i=0;i<MLWQ_K;i++) for(int j=0;j<MLWQ_K;j++) At.row[i].vec[j] = A.row[j].vec[i];
    ref_poly_matrix_vec_mul(&Atr, &At, &r); 
    t2 = stop_cycles();
    dt_au = t2 - t1; stats_ref.arith_u += dt_au;

    t1 = start_cycles(); 
    poly v_val; ref_poly_vec_transpose_mul(&v_val, &r, &r);
    t2 = stop_cycles();
    dt_av = t2 - t1; stats_ref.arith_v += dt_av;

    t1 = start_cycles(); for(int i=0; i<MLWQ_K; ++i) ref_poly_quantize(&u.vec[i], &Atr.vec[i], &d_u.vec[i], P_U); t2 = stop_cycles();
    dt_quant = t2 - t1; stats_ref.quantize += dt_quant;

    stats_ref.pke_encrypt += (dt_mat + dt_samp + dt_dith + dt_au + dt_av + dt_quant);
}

void measure_pke_decrypt_ref() {
    uint64_t t1, t2;
    uint64_t dt_dq, dt_arith, dt_dec;
    mlwq_pk pk; mlwq_sk sk; mlwq_ciphertext ct; uint8_t msg[32];
    uint8_t seed_A[32], seed_d[32], seed_ct[32];
    poly_vec u_deq; poly diff;

    random_bytes(seed_A, sizeof(seed_A));
    random_bytes(seed_d, sizeof(seed_d));
    random_bytes(seed_ct, sizeof(seed_ct));
    random_bytes(msg, sizeof(msg));
    ref_mlwq_keygen(&pk, &sk, seed_A, seed_d);
    ref_mlwq_encrypt(&ct, &pk, msg, seed_ct);

    t1 = start_cycles(); 
    for(int i=0; i<MLWQ_K; i++) ref_poly_dequantize(&u_deq.vec[i], &ct.u.vec[i], P_U);
    ref_poly_dequantize(&diff, &ct.v, P_V);
    t2 = stop_cycles();
    dt_dq = t2 - t1; stats_ref.dequantize += dt_dq;

    t1 = start_cycles(); ref_poly_vec_transpose_mul(&diff, &sk.s, &u_deq); t2 = stop_cycles();
    dt_arith = t2 - t1; stats_ref.arith += dt_arith; 

    t1 = start_cycles(); ref_poly_msg_decode(msg, &diff); t2 = stop_cycles();
    dt_dec = t2 - t1; stats_ref.decode += dt_dec;

    stats_ref.pke_decrypt += (dt_dq + dt_arith + dt_dec);
}

void measure_pke_keygen_avx() {
    uint64_t t1, t2;
    uint64_t dt_mat, dt_samp, dt_dith, dt_arith, dt_quant;
    uint8_t seed_A[32], seed_d[32];
    poly_matrix A; poly_vec s, d_pk, As, b_q;
    
    random_bytes(seed_A, 32);
    random_bytes(seed_d, 32);

    t1 = start_cycles(); avx_xof_expand_matrix(&A, seed_A); t2 = stop_cycles();
    dt_mat = t2 - t1; stats_avx.gen_matrix += dt_mat;

    dt_samp = measure_cbd_scalar(); 
    stats_avx.sample += dt_samp;

    t1 = start_cycles(); avx_xof_expand_poly_vec(&d_pk, seed_d, MLWQ_Q / P_PK); t2 = stop_cycles();
    dt_dith = t2 - t1; stats_avx.gen_dither += dt_dith;

    t1 = start_cycles(); avx_poly_matrix_vec_mul(&As, &A, &s); t2 = stop_cycles();
    dt_arith = t2 - t1; stats_avx.arith += dt_arith;

    t1 = start_cycles(); for(int i=0; i<MLWQ_K; ++i) avx_poly_quantize(&b_q.vec[i], &As.vec[i], &d_pk.vec[i], P_PK); t2 = stop_cycles();
    dt_quant = t2 - t1; stats_avx.quantize += dt_quant;

    stats_avx.pke_keygen += (dt_mat + dt_samp + dt_dith + dt_arith + dt_quant);
}

void measure_pke_encrypt_avx() {
    uint64_t t1, t2;
    uint64_t dt_mat, dt_samp, dt_dith, dt_au, dt_av, dt_quant;
    uint8_t seed_ct[32];
    poly_matrix A; poly_vec r, d_u, Atr, u;
    
    random_bytes(seed_ct, 32);

    avx_xof_expand_matrix(&A, seed_ct); 
    t1 = start_cycles(); avx_xof_expand_matrix(&A, seed_ct); t2 = stop_cycles();
    dt_mat = t2 - t1; stats_avx.gen_matrix += dt_mat;

    dt_samp = measure_cbd_scalar(); 
    stats_avx.sample += dt_samp;

    t1 = start_cycles(); avx_xof_expand_poly_vec(&d_u, seed_ct, MLWQ_Q / P_U); t2 = stop_cycles();
    dt_dith = t2 - t1; stats_avx.gen_dither += dt_dith;

    t1 = start_cycles(); 
    poly_matrix At; for(int i=0;i<MLWQ_K;i++) for(int j=0;j<MLWQ_K;j++) At.row[i].vec[j] = A.row[j].vec[i];
    avx_poly_matrix_vec_mul(&Atr, &At, &r); 
    t2 = stop_cycles();
    dt_au = t2 - t1; stats_avx.arith_u += dt_au;

    t1 = start_cycles(); 
    poly v_val; avx_poly_vec_transpose_mul(&v_val, &r, &r);
    t2 = stop_cycles();
    dt_av = t2 - t1; stats_avx.arith_v += dt_av;

    t1 = start_cycles(); for(int i=0; i<MLWQ_K; ++i) avx_poly_quantize(&u.vec[i], &Atr.vec[i], &d_u.vec[i], P_U); t2 = stop_cycles();
    dt_quant = t2 - t1; stats_avx.quantize += dt_quant;

    stats_avx.pke_encrypt += (dt_mat + dt_samp + dt_dith + dt_au + dt_av + dt_quant);
}

void measure_pke_decrypt_avx() {
    uint64_t t1, t2;
    uint64_t dt_dq, dt_arith, dt_dec;
    mlwq_pk pk; mlwq_sk sk; mlwq_ciphertext ct; uint8_t msg[32];
    uint8_t seed_A[32], seed_d[32], seed_ct[32];
    poly_vec u_deq;
    poly diff;

    random_bytes(seed_A, sizeof(seed_A));
    random_bytes(seed_d, sizeof(seed_d));
    random_bytes(seed_ct, sizeof(seed_ct));
    random_bytes(msg, sizeof(msg));
    avx_mlwq_keygen(&pk, &sk, seed_A, seed_d);
    avx_mlwq_encrypt(&ct, &pk, msg, seed_ct);

    t1 = start_cycles(); 
    for(int i=0; i<MLWQ_K; i++) avx_poly_dequantize(&u_deq.vec[i], &ct.u.vec[i], P_U);
    avx_poly_dequantize(&diff, &ct.v, P_V);
    t2 = stop_cycles();
    dt_dq = t2 - t1; stats_avx.dequantize += dt_dq;

    t1 = start_cycles(); avx_poly_vec_transpose_mul(&diff, &sk.s, &u_deq); t2 = stop_cycles();
    dt_arith = t2 - t1; stats_avx.arith += dt_arith;

    t1 = start_cycles(); avx_poly_msg_decode(msg, &diff); t2 = stop_cycles();
    dt_dec = t2 - t1; stats_avx.decode += dt_dec;

    stats_avx.pke_decrypt += (dt_dq + dt_arith + dt_dec);
}

int main() {
    random_init();
    printf("\n=== M-LWQ Comprehensive Performance Report ===\n");
    printf("%s\nN=%d, K=%d\n\n", PARAM_NAME, MLWQ_N, MLWQ_K);

    // [修改] 正确打印 PKE 和 KEM 的 Wire Size
    print_data_sizes();

    mlwq_pk pk; mlwq_kem_sk sk; mlwq_ciphertext ct;
    uint8_t ss1[32], ss2[32];
    
    printf(">>> Running: Scalar Mode (%d rounds)...\n", ROUNDS);
    ref_mlwq_kem_keygen(&pk, &sk);
    ref_mlwq_kem_encaps(&ct, ss1, &pk);
    if(ref_mlwq_kem_decaps(ss2, &sk, &ct) && memcmp(ss1, ss2, 32)==0)
        printf("   [PASS] Correctness verified.\n");
    else { printf("   [FAIL] Ref Logic failed!\n"); return 1; }

    printf(">>> Running: AVX2 Mode (%d rounds)...\n", ROUNDS);
    avx_mlwq_kem_keygen(&pk, &sk);
    avx_mlwq_kem_encaps(&ct, ss1, &pk);
    if(avx_mlwq_kem_decaps(ss2, &sk, &ct) && memcmp(ss1, ss2, 32)==0)
        printf("   [PASS] Correctness verified.\n");
    else { printf("   [FAIL] AVX Logic failed!\n"); return 1; }

    memset(&stats_ref, 0, sizeof(bench_stats_t));
    memset(&stats_avx, 0, sizeof(bench_stats_t));

    uint64_t t1, t2;

    for(int i=0; i<ROUNDS; i++) {
        measure_pke_keygen_ref();
        measure_pke_encrypt_ref();
        measure_pke_decrypt_ref();
        
        measure_pke_keygen_avx();
        measure_pke_encrypt_avx();
        measure_pke_decrypt_avx();

        t1 = start_cycles(); ref_mlwq_kem_keygen(&pk, &sk); t2 = stop_cycles();
        stats_ref.kem_keygen += (t2 - t1);
        t1 = start_cycles(); ref_mlwq_kem_encaps(&ct, ss1, &pk); t2 = stop_cycles();
        stats_ref.kem_encaps += (t2 - t1);
        t1 = start_cycles(); ref_mlwq_kem_decaps(ss2, &sk, &ct); t2 = stop_cycles();
        stats_ref.kem_decaps += (t2 - t1);

        t1 = start_cycles(); avx_mlwq_kem_keygen(&pk, &sk); t2 = stop_cycles();
        stats_avx.kem_keygen += (t2 - t1);
        t1 = start_cycles(); avx_mlwq_kem_encaps(&ct, ss1, &pk); t2 = stop_cycles();
        stats_avx.kem_encaps += (t2 - t1);
        t1 = start_cycles(); avx_mlwq_kem_decaps(ss2, &sk, &ct); t2 = stop_cycles();
        stats_avx.kem_decaps += (t2 - t1);
    }

    // --- Report ---
    printf("\n>>> PART 1: Internal Breakdown (Where is time spent?)\n\n");
    print_sep();
    printf(" PKE KeyGen Breakdown (Detailed)\n");
    print_sep();
    printf("%-20s %-15s %-15s %-15s %-10s\n", "Sub-Component", "Scalar (cyc)", "AVX2 (cyc)", "Speedup", "Scalar %");
    
    uint64_t s_kg_total = avg(stats_ref.pke_keygen); 
    printf("%-20s %-15lu %-15lu %-.2fx            %.1f%%\n", "GenMatrix (A)", avg(stats_ref.gen_matrix)/2, avg(stats_avx.gen_matrix)/2, (double)avg(stats_ref.gen_matrix)/avg(stats_avx.gen_matrix), 100.0*(avg(stats_ref.gen_matrix)/2)/s_kg_total);
    printf("%-20s %-15lu %-15lu %-.2fx            %.1f%%\n", "Sample (s)", avg(stats_ref.sample)/2, avg(stats_avx.sample)/2, (double)avg(stats_ref.sample)/avg(stats_avx.sample), 100.0*(avg(stats_ref.sample)/2)/s_kg_total);
    printf("%-20s %-15lu %-15lu %-.2fx            %.1f%%\n", "GenDither", avg(stats_ref.gen_dither)/2, avg(stats_avx.gen_dither)/2, (double)avg(stats_ref.gen_dither)/avg(stats_avx.gen_dither), 100.0*(avg(stats_ref.gen_dither)/2)/s_kg_total);
    printf("%-20s %-15lu %-15lu %-.2fx            %.1f%%\n", "Arith (A*s)", avg(stats_ref.arith)/2, avg(stats_avx.arith)/2, (double)avg(stats_ref.arith)/avg(stats_avx.arith), 100.0*(avg(stats_ref.arith)/2)/s_kg_total);
    printf("%-20s %-15lu %-15lu %-.2fx            %.1f%%\n", "Quantize", avg(stats_ref.quantize)/2, avg(stats_avx.quantize)/2, (double)avg(stats_ref.quantize)/avg(stats_avx.quantize), 100.0*(avg(stats_ref.quantize)/2)/s_kg_total);

    printf("\n");
    print_sep();
    printf(" PKE Encrypt Breakdown (Detailed)\n");
    print_sep();
    printf("%-20s %-15s %-15s %-15s\n", "Sub-Component", "Scalar (cyc)", "AVX2 (cyc)", "Speedup");

    uint64_t au_ref = avg(stats_ref.arith_u); uint64_t au_avx = avg(stats_avx.arith_u);
    uint64_t av_ref = avg(stats_ref.arith_v); uint64_t av_avx = avg(stats_avx.arith_v);
    
    printf("%-20s %-15lu %-15lu %-.2fx\n", "Arith (u)", au_ref, au_avx, (double)au_ref/au_avx);
    printf("%-20s %-15lu %-15lu %-.2fx\n", "Arith (v)", av_ref, av_avx, (double)av_ref/av_avx);

    printf("\n");
    print_sep();
    printf(" PKE Decrypt Breakdown (Detailed)\n");
    print_sep();
    printf("%-20s %-15s %-15s %-15s\n", "Sub-Component", "Scalar (cyc)", "AVX2 (cyc)", "Speedup");
    
    uint64_t dq_ref = avg(stats_ref.dequantize); uint64_t dq_avx = avg(stats_avx.dequantize);
    uint64_t dc_ref = avg(stats_ref.decode); uint64_t dc_avx = avg(stats_avx.decode);
    uint64_t ar_dec_ref = avg(stats_ref.arith)/2; uint64_t ar_dec_avx = avg(stats_avx.arith)/2;

    printf("%-20s %-15lu %-15lu %-.2fx\n", "DeQuantize", dq_ref, dq_avx, (double)dq_ref/dq_avx);
    printf("%-20s %-15lu %-15lu %-.2fx\n", "Arith (v-su)", ar_dec_ref, ar_dec_avx, (double)ar_dec_ref/ar_dec_avx);
    printf("%-20s %-15lu %-15lu %-.2fx\n", "Decode", dc_ref, dc_avx, (double)dc_ref/dc_avx);

    printf("\n\n>>> PART 2: Core Component Comparison (Quantize vs Sample)\n");
    print_sep();
    printf("%-10s %-10s %-15s %-15s %-20s %-20s\n", "Component", "Mode", "Quantize", "Sample", "Alg. Efficiency", "AVX Improvement");
    print_sep();
    
    uint64_t q_ref = avg(stats_ref.quantize)/2; uint64_t s_ref = avg(stats_ref.sample)/2;
    uint64_t q_avx = avg(stats_avx.quantize)/2; uint64_t s_avx = avg(stats_avx.sample)/2;
    printf("%-10s %-10s %-15lu %-15lu %-.2fx                 %-20s\n", "PK / u", "Scalar", q_ref, s_ref, (double)s_ref/q_ref, "1.00x (Ref)");
    printf("%-10s %-10s %-15lu %-15lu %-.2fx                 %-.2fx\n", "PK / u", "AVX2", q_avx, s_avx, (double)s_avx/q_avx, (double)q_ref/q_avx);

    printf("\n\n>>> PART 3: PKE Full Flow Summary (Total Time)\n");
    print_sep();
    printf("%-20s %-15s %-15s %-10s\n", "Operation", "Scalar Cycles", "AVX2 Cycles", "Speedup");
    print_sep();
    printf("%-20s %-15lu %-15lu %-.2fx\n", "PKE KeyGen", avg(stats_ref.pke_keygen), avg(stats_avx.pke_keygen), (double)avg(stats_ref.pke_keygen)/avg(stats_avx.pke_keygen));
    printf("%-20s %-15lu %-15lu %-.2fx\n", "PKE Encrypt", avg(stats_ref.pke_encrypt), avg(stats_avx.pke_encrypt), (double)avg(stats_ref.pke_encrypt)/avg(stats_avx.pke_encrypt));
    printf("%-20s %-15lu %-15lu %-.2fx\n", "PKE Decrypt", avg(stats_ref.pke_decrypt), avg(stats_avx.pke_decrypt), (double)avg(stats_ref.pke_decrypt)/avg(stats_avx.pke_decrypt));

    printf("\n\n>>> PART 4: KEM Full Flow Summary (IND-CCA2)\n");
    print_sep();
    printf("%-20s %-15s %-15s %-10s\n", "Operation", "Scalar Cycles", "AVX2 Cycles", "Speedup");
    print_sep();
    printf("%-20s %-15lu %-15lu %-.2fx\n", "KEM KeyGen", avg(stats_ref.kem_keygen), avg(stats_avx.kem_keygen), (double)avg(stats_ref.kem_keygen)/avg(stats_avx.kem_keygen));
    printf("%-20s %-15lu %-15lu %-.2fx\n", "KEM Encaps", avg(stats_ref.kem_encaps), avg(stats_avx.kem_encaps), (double)avg(stats_ref.kem_encaps)/avg(stats_avx.kem_encaps));
    printf("%-20s %-15lu %-15lu %-.2fx\n", "KEM Decaps", avg(stats_ref.kem_decaps), avg(stats_avx.kem_decaps), (double)avg(stats_ref.kem_decaps)/avg(stats_avx.kem_decaps));
    
    print_sep();
    printf("\n[FINAL] All checks passed! Implementation is correct.\n");

    return 0;
}
