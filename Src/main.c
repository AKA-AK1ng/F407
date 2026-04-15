/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "rng.h"
#include "rtc.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "stdio.h"  // 用于printf
#include "string.h"
#include "random.h"
#include "params.h"
#include "../ref/poly.h"
#include "../ref/xof.h"
#include "../ref/mlwq.h"
#include "../kyber_ref/api.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
#define PROFILE_SEPARATOR "----------------------------------------------------------------------------------------------\r\n"
#define MLWQ_BENCH_ROUNDS 1000u
#define MLWQ_BENCH_PROGRESS_STEP 100u
#define MLWQ_KEM_DECAPS_SUCCESS 1
#define KEM_SCHEME_COL_WIDTH 12
#define KEM_CYCLES_COL_WIDTH 12
#define KEM_MISMATCH_COL_WIDTH 8
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
// 串口接收变量
uint8_t rx_buffer;        // 单字节接收缓存
uint8_t cmd_flag = 0;     // 指令有效标志
char cmd;                 // 存储接收到的指令

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */
static void run_mlwq_benchmark(void);
static void run_kem_comparison_benchmark(void);
static void enable_cycle_counter(void);
static void run_kyber_benchmark(uint32_t rounds, uint64_t *keygen_total, uint64_t *encaps_total, uint64_t *decaps_total, uint32_t *mismatch_count);

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
int __io_putchar(int ch)
{
  // 轮询发送1字节，超时100ms（适配USART1）
  HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 100);
  return ch;
}
// 兼容fputc写法（双重保险，适配MicroLib/其他场景）
int fputc(int ch, FILE *f)
{
  return __io_putchar(ch);
}
// 串口接收完成回调（收到1个字节就触发）
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
  if(huart->Instance == USART1)
  {
    // 读取接收到的指令
    cmd = rx_buffer;
    // 置位指令标志
    cmd_flag = 1;
    // 重新开启接收（无限次指令）
    HAL_UART_Receive_IT(&huart1, &rx_buffer, 1);
  }
}

typedef struct {
  uint64_t key_genA;
  uint64_t key_sample_s;
  uint64_t key_gendither;
  uint64_t key_arith_as;
  uint64_t key_quantize;

  uint64_t enc_genA;
  uint64_t enc_sample_r;
  uint64_t enc_gendither_u;
  uint64_t enc_arith_u;
  uint64_t enc_arith_v;
  uint64_t enc_quantize_u;

  uint64_t dec_deq;
  uint64_t dec_arith;
  uint64_t dec_decode;

  uint64_t pke_keygen;
  uint64_t pke_encrypt;
  uint64_t pke_decrypt;

  uint64_t kem_keygen;
  uint64_t kem_encaps;
  uint64_t kem_decaps;

  uint32_t pke_mismatch_count;
  uint32_t kem_mismatch_count;
} mlwq_bench_totals_t;

typedef struct {
  const char *name;
  uint64_t keygen_cycles;
  uint64_t encaps_cycles;
  uint64_t decaps_cycles;
  uint32_t mismatch_count;
} kem_summary_t;

static uint64_t bench_avg(uint64_t total)
{
  return total / MLWQ_BENCH_ROUNDS;
}

static void enable_cycle_counter(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;
}

static void run_mlwq_kem_benchmark(uint32_t rounds,
                                   uint64_t *keygen_total,
                                   uint64_t *encaps_total,
                                   uint64_t *decaps_total,
                                   uint32_t *mismatch_count)
{
  static mlwq_pk pk;
  static mlwq_kem_sk sk;
  static mlwq_ciphertext ct;
  static uint8_t ss1[MLWQ_SSBYTES], ss2[MLWQ_SSBYTES];
  uint32_t t0;
  int dec_ok;

  *keygen_total = 0;
  *encaps_total = 0;
  *decaps_total = 0;
  *mismatch_count = 0;

  for(uint32_t round = 0; round < rounds; round++)
  {
    t0 = DWT->CYCCNT;
    ref_mlwq_kem_keygen(&pk, &sk);
    *keygen_total += (uint64_t)(DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    ref_mlwq_kem_encaps(&ct, ss1, &pk);
    *encaps_total += (uint64_t)(DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    dec_ok = ref_mlwq_kem_decaps(ss2, &sk, &ct);
    *decaps_total += (uint64_t)(DWT->CYCCNT - t0);

    if((dec_ok != MLWQ_KEM_DECAPS_SUCCESS) || (memcmp(ss1, ss2, MLWQ_SSBYTES) != 0)) {
      (*mismatch_count)++;
    }
  }
}

static void run_kyber_benchmark(uint32_t rounds,
                                uint64_t *keygen_total,
                                uint64_t *encaps_total,
                                uint64_t *decaps_total,
                                uint32_t *mismatch_count)
{
  static uint8_t pk[pqcrystals_kyber512_ref_PUBLICKEYBYTES];
  static uint8_t sk[pqcrystals_kyber512_ref_SECRETKEYBYTES];
  static uint8_t ct[pqcrystals_kyber512_ref_CIPHERTEXTBYTES];
  static uint8_t ss1[pqcrystals_kyber512_ref_BYTES], ss2[pqcrystals_kyber512_ref_BYTES];
  uint32_t t0;
  int dec_ret;

  *keygen_total = 0;
  *encaps_total = 0;
  *decaps_total = 0;
  *mismatch_count = 0;

  for(uint32_t round = 0; round < rounds; round++)
  {
    t0 = DWT->CYCCNT;
    (void)pqcrystals_kyber512_ref_keypair(pk, sk);
    *keygen_total += (uint64_t)(DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    (void)pqcrystals_kyber512_ref_enc(ct, ss1, pk);
    *encaps_total += (uint64_t)(DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    dec_ret = pqcrystals_kyber512_ref_dec(ss2, ct, sk);
    *decaps_total += (uint64_t)(DWT->CYCCNT - t0);

    if((dec_ret != 0) || (memcmp(ss1, ss2, pqcrystals_kyber512_ref_BYTES) != 0)) {
      (*mismatch_count)++;
    }
  }
}

static void print_kem_summary_row(const kem_summary_t *summary, uint32_t rounds)
{
  printf("%-*s | %*lu | %*lu | %*lu | %*lu\r\n",
         KEM_SCHEME_COL_WIDTH,
         summary->name,
         KEM_CYCLES_COL_WIDTH,
         (unsigned long)(summary->keygen_cycles / rounds),
         KEM_CYCLES_COL_WIDTH,
         (unsigned long)(summary->encaps_cycles / rounds),
         KEM_CYCLES_COL_WIDTH,
         (unsigned long)(summary->decaps_cycles / rounds),
         KEM_MISMATCH_COL_WIDTH,
         (unsigned long)summary->mismatch_count);
}

static void print_data_sizes(void)
{
  printf(">>> PART 0: Protocol Data Sizes (Serialized/Wire Format)\r\n");
  printf("%s", PROFILE_SEPARATOR);
  printf("%-35s %-15s\r\n", "Component", "Size (Bytes)");
  printf("%s", PROFILE_SEPARATOR);
  printf("[PKE] Public Key (pk):\r\n");
  printf("  %-33s %d\r\n", "MLWQ_PUBLICKEYBYTES", MLWQ_PUBLICKEYBYTES);
  printf("[PKE] Secret Key (sk):\r\n");
  printf("  %-33s %d\r\n", "MLWQ_SECRETKEYBYTES", MLWQ_SECRETKEYBYTES);
  printf("[PKE] Ciphertext (ct):\r\n");
  printf("  %-33s %d\r\n\r\n", "MLWQ_CIPHERTEXTBYTES", MLWQ_CIPHERTEXTBYTES);

  printf("[KEM] Public Key:\r\n");
  printf("  %-33s %d\r\n", "Same as PKE PK", MLWQ_PUBLICKEYBYTES);
  printf("[KEM] Secret Key (Bundled):\r\n");
  printf("  %-33s %d (Approx. Theoretical)\r\n",
         "sk + pk + H(pk) + z",
         (int)(MLWQ_SECRETKEYBYTES + MLWQ_PUBLICKEYBYTES + 32 + 32));
  printf("[KEM] Ciphertext:\r\n");
  printf("  %-33s %d\r\n", "Same as PKE CT", MLWQ_CIPHERTEXTBYTES);
  printf("[KEM] Shared Secret (ss):\r\n");
  printf("  %-33s %d\r\n", "MLWQ_SSBYTES", MLWQ_SSBYTES);
  printf("%s\r\n", PROFILE_SEPARATOR);
}

static void measure_pke_keygen_round(mlwq_bench_totals_t *totals)
{
  static poly_matrix A;
  static poly_vec s, d_pk, As, b_q;
  static uint8_t seed_A[SEEDBYTES], seed_d[SEEDBYTES], seed_s[SEEDBYTES], d_seed[33];
  uint32_t t0;
  uint64_t dt_mat, dt_samp, dt_dith, dt_arith, dt_quant;

  random_bytes(seed_A, sizeof(seed_A));
  random_bytes(seed_d, sizeof(seed_d));
  random_bytes(seed_s, sizeof(seed_s));

  t0 = DWT->CYCCNT;
  ref_xof_expand_matrix(&A, seed_A);
  dt_mat = (uint64_t)(DWT->CYCCNT - t0);
  totals->key_genA += dt_mat;

  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_getnoise_eta1(&s.vec[i], seed_s, (uint8_t)i);
  }
  dt_samp = (uint64_t)(DWT->CYCCNT - t0);
  totals->key_sample_s += dt_samp;

  for(int i = 0; i < SEEDBYTES; i++) d_seed[i] = seed_d[i];
  d_seed[SEEDBYTES] = 0xFF;
  t0 = DWT->CYCCNT;
  ref_xof_expand_poly_vec(&d_pk, d_seed, MLWQ_Q / P_PK);
  dt_dith = (uint64_t)(DWT->CYCCNT - t0);
  totals->key_gendither += dt_dith;

  t0 = DWT->CYCCNT;
  ref_poly_matrix_vec_mul(&As, &A, &s);
  dt_arith = (uint64_t)(DWT->CYCCNT - t0);
  totals->key_arith_as += dt_arith;

  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; ++i) {
    ref_poly_quantize(&b_q.vec[i], &As.vec[i], &d_pk.vec[i], P_PK);
  }
  dt_quant = (uint64_t)(DWT->CYCCNT - t0);
  totals->key_quantize += dt_quant;

  totals->pke_keygen += (dt_mat + dt_samp + dt_dith + dt_arith + dt_quant);
}

static void measure_pke_encrypt_round(mlwq_bench_totals_t *totals)
{
  static mlwq_pk pk;
  static mlwq_sk sk;
  static poly_matrix A, At;
  static poly_vec r, d_u, Atr, u_q, b_deq;
  static poly v_val;
  static uint8_t seed_A[SEEDBYTES], seed_d[SEEDBYTES], seed_ct[SEEDBYTES], d_seed[33];
  uint32_t t0;
  uint64_t dt_mat, dt_samp, dt_dith, dt_au, dt_av, dt_quant;

  random_bytes(seed_A, sizeof(seed_A));
  random_bytes(seed_d, sizeof(seed_d));
  random_bytes(seed_ct, sizeof(seed_ct));
  ref_mlwq_keygen(&pk, &sk, seed_A, seed_d);

  t0 = DWT->CYCCNT;
  ref_xof_expand_matrix(&A, pk.seed_A);
  dt_mat = (uint64_t)(DWT->CYCCNT - t0);
  totals->enc_genA += dt_mat;

  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_getnoise_eta1(&r.vec[i], seed_ct, (uint8_t)i);
  }
  dt_samp = (uint64_t)(DWT->CYCCNT - t0);
  totals->enc_sample_r += dt_samp;

  for(int i = 0; i < SEEDBYTES; i++) d_seed[i] = seed_ct[i];
  d_seed[SEEDBYTES] = 10;
  t0 = DWT->CYCCNT;
  ref_xof_expand_poly_vec(&d_u, d_seed, MLWQ_Q / P_U);
  dt_dith = (uint64_t)(DWT->CYCCNT - t0);
  totals->enc_gendither_u += dt_dith;

  for(int i = 0; i < MLWQ_K; i++) {
    for(int j = 0; j < MLWQ_K; j++) {
      At.row[i].vec[j] = A.row[j].vec[i];
    }
  }
  t0 = DWT->CYCCNT;
  ref_poly_matrix_vec_mul(&Atr, &At, &r);
  dt_au = (uint64_t)(DWT->CYCCNT - t0);
  totals->enc_arith_u += dt_au;

  for(int i = 0; i < MLWQ_K; ++i) {
    ref_poly_dequantize(&b_deq.vec[i], &pk.b_q.vec[i], P_PK);
  }
  t0 = DWT->CYCCNT;
  ref_poly_vec_transpose_mul(&v_val, &b_deq, &r);
  dt_av = (uint64_t)(DWT->CYCCNT - t0);
  totals->enc_arith_v += dt_av;

  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; ++i) {
    ref_poly_quantize(&u_q.vec[i], &Atr.vec[i], &d_u.vec[i], P_U);
  }
  dt_quant = (uint64_t)(DWT->CYCCNT - t0);
  totals->enc_quantize_u += dt_quant;

  totals->pke_encrypt += (dt_mat + dt_samp + dt_dith + dt_au + dt_av + dt_quant);
}

static void measure_pke_decrypt_round(mlwq_bench_totals_t *totals)
{
  static mlwq_pk pk;
  static mlwq_sk sk;
  static mlwq_ciphertext ct;
  static poly_vec u_deq;
  static poly v_deq, s_t_u, diff;
  static uint8_t msg_in[32], msg_out[32];
  static uint8_t seed_A[SEEDBYTES], seed_d[SEEDBYTES], seed_ct[SEEDBYTES];
  uint32_t t0;
  uint64_t dt_dq, dt_arith, dt_dec;

  random_bytes(seed_A, sizeof(seed_A));
  random_bytes(seed_d, sizeof(seed_d));
  random_bytes(seed_ct, sizeof(seed_ct));
  random_bytes(msg_in, sizeof(msg_in));
  ref_mlwq_keygen(&pk, &sk, seed_A, seed_d);
  ref_mlwq_encrypt(&ct, &pk, msg_in, seed_ct);

  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_dequantize(&u_deq.vec[i], &ct.u.vec[i], P_U);
  }
  ref_poly_dequantize(&v_deq, &ct.v, P_V);
  dt_dq = (uint64_t)(DWT->CYCCNT - t0);
  totals->dec_deq += dt_dq;

  t0 = DWT->CYCCNT;
  ref_poly_vec_transpose_mul(&s_t_u, &sk.s, &u_deq);
  ref_poly_sub(&diff, &v_deq, &s_t_u);
  dt_arith = (uint64_t)(DWT->CYCCNT - t0);
  totals->dec_arith += dt_arith;

  t0 = DWT->CYCCNT;
  ref_poly_msg_decode(msg_out, &diff);
  dt_dec = (uint64_t)(DWT->CYCCNT - t0);
  totals->dec_decode += dt_dec;

  totals->pke_decrypt += (dt_dq + dt_arith + dt_dec);
  if(memcmp(msg_in, msg_out, sizeof(msg_in)) != 0) {
    totals->pke_mismatch_count++;
  }
}

static void measure_kem_round(mlwq_bench_totals_t *totals)
{
  static mlwq_pk pk;
  static mlwq_kem_sk sk;
  static mlwq_ciphertext ct;
  static uint8_t ss1[MLWQ_SSBYTES], ss2[MLWQ_SSBYTES];
  uint32_t t0;
  int dec_ok;

  t0 = DWT->CYCCNT;
  ref_mlwq_kem_keygen(&pk, &sk);
  totals->kem_keygen += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  ref_mlwq_kem_encaps(&ct, ss1, &pk);
  totals->kem_encaps += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  dec_ok = ref_mlwq_kem_decaps(ss2, &sk, &ct);
  totals->kem_decaps += (uint64_t)(DWT->CYCCNT - t0);

  if((dec_ok != MLWQ_KEM_DECAPS_SUCCESS) || (memcmp(ss1, ss2, MLWQ_SSBYTES) != 0)) {
    totals->kem_mismatch_count++;
  }
}

static void run_mlwq_benchmark(void)
{
  mlwq_bench_totals_t totals = {0};
  uint64_t q_avg, s_avg;
  uint32_t correctness_ok;

  printf("\r\n=== M-LWQ Comprehensive Performance Report (STM32 Scalar) ===\r\n");
  printf("%sN=%d, K=%d\r\n\r\n", PARAM_NAME, MLWQ_N, MLWQ_K);
  print_data_sizes();

  printf(">>> Running scalar correctness check...\r\n");
  {
    mlwq_pk pk;
    mlwq_kem_sk sk;
    mlwq_ciphertext ct;
    uint8_t ss1[MLWQ_SSBYTES], ss2[MLWQ_SSBYTES];
    ref_mlwq_kem_keygen(&pk, &sk);
    ref_mlwq_kem_encaps(&ct, ss1, &pk);
    correctness_ok = ((ref_mlwq_kem_decaps(ss2, &sk, &ct) == MLWQ_KEM_DECAPS_SUCCESS) &&
                      (memcmp(ss1, ss2, MLWQ_SSBYTES) == 0));
  }
  printf("   [%s] Correctness verified.\r\n", correctness_ok ? "PASS" : "FAIL");
  if(!correctness_ok) {
    printf("Abort benchmark due to failed correctness check.\r\n\r\n");
    return;
  }

  printf(">>> Running benchmark (%lu rounds)...\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("TEST POINTS: KG=[GenMatrix/Sample/GenDither/Arith/Quantize] ");
  printf("ENC=[GenMatrix/Sample/GenDither/Arith(u)/Arith(v)/Quantize(u)] DEC=[DeQuant/Arith/Decode] ");
  printf("KEM=[KeyGen/Encaps/Decaps]\r\n");

  enable_cycle_counter();

  for(uint32_t round = 0; round < MLWQ_BENCH_ROUNDS; round++)
  {
    measure_pke_keygen_round(&totals);
    measure_pke_encrypt_round(&totals);
    measure_pke_decrypt_round(&totals);
    measure_kem_round(&totals);

    if(((round + 1u) % MLWQ_BENCH_PROGRESS_STEP) == 0u) {
      printf("BENCH PROGRESS: %lu/%lu\r\n",
             (unsigned long)(round + 1u),
             (unsigned long)MLWQ_BENCH_ROUNDS);
    }
  }

  printf("\r\n>>> PART 1: Internal Breakdown (Scalar)\r\n");
  printf("%s", PROFILE_SEPARATOR);
  printf(" PKE KeyGen Breakdown (Avg, %lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("GenMatrix (A): %lu\r\n", (unsigned long)bench_avg(totals.key_genA));
  printf("Sample (s): %lu\r\n", (unsigned long)bench_avg(totals.key_sample_s));
  printf("GenDither: %lu\r\n", (unsigned long)bench_avg(totals.key_gendither));
  printf("Arith (A*s): %lu\r\n", (unsigned long)bench_avg(totals.key_arith_as));
  printf("Quantize: %lu\r\n", (unsigned long)bench_avg(totals.key_quantize));

  printf("\r\n%s", PROFILE_SEPARATOR);
  printf(" PKE Encrypt Breakdown (Avg, %lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("GenMatrix (A): %lu\r\n", (unsigned long)bench_avg(totals.enc_genA));
  printf("Sample (r): %lu\r\n", (unsigned long)bench_avg(totals.enc_sample_r));
  printf("GenDither (u): %lu\r\n", (unsigned long)bench_avg(totals.enc_gendither_u));
  printf("Arith (u): %lu\r\n", (unsigned long)bench_avg(totals.enc_arith_u));
  printf("Arith (v): %lu\r\n", (unsigned long)bench_avg(totals.enc_arith_v));
  printf("Quantize (u): %lu\r\n", (unsigned long)bench_avg(totals.enc_quantize_u));

  printf("\r\n%s", PROFILE_SEPARATOR);
  printf(" PKE Decrypt Breakdown (Avg, %lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("DeQuantize: %lu\r\n", (unsigned long)bench_avg(totals.dec_deq));
  printf("Arith (v-su): %lu\r\n", (unsigned long)bench_avg(totals.dec_arith));
  printf("Decode: %lu\r\n", (unsigned long)bench_avg(totals.dec_decode));

  printf("\r\n>>> PART 2: Core Component Comparison (Quantize vs Sample)\r\n");
  printf("%s", PROFILE_SEPARATOR);
  q_avg = bench_avg(totals.key_quantize);
  s_avg = bench_avg(totals.key_sample_s);
  printf("KeyGen Quantize avg: %lu\r\n", (unsigned long)q_avg);
  printf("KeyGen Sample avg: %lu\r\n", (unsigned long)s_avg);
  if(q_avg != 0u) {
    printf("Sample/Quantize ratio: %lu.%02lu x\r\n",
           (unsigned long)(s_avg / q_avg),
           (unsigned long)((s_avg % q_avg) * 100u / q_avg));
  } else {
    printf("Sample/Quantize ratio: N/A\r\n");
  }

  printf("\r\n>>> PART 3: PKE Full Flow Summary (Total Time)\r\n");
  printf("%s", PROFILE_SEPARATOR);
  printf("PKE KeyGen: %lu\r\n", (unsigned long)bench_avg(totals.pke_keygen));
  printf("PKE Encrypt: %lu\r\n", (unsigned long)bench_avg(totals.pke_encrypt));
  printf("PKE Decrypt: %lu\r\n", (unsigned long)bench_avg(totals.pke_decrypt));

  printf("\r\n>>> PART 4: KEM Full Flow Summary (IND-CCA2)\r\n");
  printf("%s", PROFILE_SEPARATOR);
  printf("KEM KeyGen: %lu\r\n", (unsigned long)bench_avg(totals.kem_keygen));
  printf("KEM Encaps: %lu\r\n", (unsigned long)bench_avg(totals.kem_encaps));
  printf("KEM Decaps: %lu\r\n", (unsigned long)bench_avg(totals.kem_decaps));

  printf("\r\nPKE decode mismatch count: %lu\r\n", (unsigned long)totals.pke_mismatch_count);
  printf("KEM shared-secret mismatch count: %lu\r\n", (unsigned long)totals.kem_mismatch_count);
  printf("[FINAL] Benchmark complete.\r\n\r\n");
}

static void run_kem_comparison_benchmark(void)
{
  kem_summary_t kyber_summary = {"Kyber512", 0, 0, 0, 0};

  printf("\r\n=== Kyber512 Cycles Quick Benchmark (%lu rounds) ===\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  enable_cycle_counter();

  run_kyber_benchmark(MLWQ_BENCH_ROUNDS,
                      &kyber_summary.keygen_cycles,
                      &kyber_summary.encaps_cycles,
                      &kyber_summary.decaps_cycles,
                      &kyber_summary.mismatch_count);

  printf("%s", PROFILE_SEPARATOR);
  printf("%-*s | %-*s | %-*s | %-*s | %-*s\r\n",
         KEM_SCHEME_COL_WIDTH,
         "Scheme",
         KEM_CYCLES_COL_WIDTH,
         "KeyGen",
         KEM_CYCLES_COL_WIDTH,
         "Encaps",
         KEM_CYCLES_COL_WIDTH,
         "Decaps",
         KEM_MISMATCH_COL_WIDTH,
         "Mismatch");
  printf("%s", PROFILE_SEPARATOR);
  print_kem_summary_row(&kyber_summary, MLWQ_BENCH_ROUNDS);
  printf("%s\r\n", PROFILE_SEPARATOR);
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  // 1. 底层初始化
  HAL_Init();
  SystemClock_Config();

  // 2. 外设初始化
  MX_GPIO_Init();
  MX_USART1_UART_Init();
  MX_RNG_Init();
  //random_init();


  // 3. 启动串口中断接收
  HAL_UART_Receive_IT(&huart1, &rx_buffer, 1);

  /* USER CODE BEGIN 2 */
  // 开机提示
  printf("=========================\r\n");
  printf("  MLWQ TEST SYSTEM READY\r\n");
  printf("=========================\r\n");
  printf("CMD: M=RUN COMPREHENSIVE SCALAR BENCHMARK (%lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("CMD: C=RUN KYBER512 CYCLE TABLE (%lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("BUILD MODE: KYBER-ONLY BENCHMARK\r\n");
  printf("=========================\r\n");
  /* USER CODE END 2 */

  // 4. 主循环
  while (1)
  {
    if(cmd_flag == 1)
    {
      cmd_flag = 0;

      if(cmd == 'M' || cmd == 'm')
      {
        run_mlwq_benchmark();
      }
      else if(cmd == 'C' || cmd == 'c')
      {
        run_kem_comparison_benchmark();
      }
      else
      {
        printf("ONLY CMD 'M'/'C' ARE ENABLED\r\n\r\n");
      }
    }
  }
}
/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI|RCC_OSCILLATORTYPE_LSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.LSIState = RCC_LSI_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 168;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
