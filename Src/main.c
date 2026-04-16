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
#include "stdio.h"
#include "string.h"
#include "../kyber_ref/api.h"
#include "../kyber_ref/params.h"
#include "../kyber_ref/indcpa.h"
#include "../kyber_ref/polyvec.h"
#include "../kyber_ref/poly.h"
#include "../kyber_ref/symmetric.h"
#include "../kyber_ref/randombytes.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

typedef struct {
  const char *name;
  uint64_t keygen_cycles;
  uint64_t encaps_cycles;
  uint64_t decaps_cycles;
  uint32_t keygen_success_count;
  uint32_t encaps_success_count;
  uint32_t decaps_success_count;
  uint32_t error_count;
  uint32_t mismatch_count;
} kem_summary_t;

typedef struct {
  uint64_t total;
  uint32_t min;
  uint32_t max;
  uint32_t count;
} cycle_stat_t;

typedef struct {
  cycle_stat_t keypair_total;
  cycle_stat_t keypair_derand_total;
  cycle_stat_t rng;
  cycle_stat_t indcpa_total;
  cycle_stat_t kem_tail;
  cycle_stat_t seed_expand;
  cycle_stat_t gen_matrix;
  cycle_stat_t sample;
  cycle_stat_t ntt;
  cycle_stat_t matvec;
  cycle_stat_t add_reduce;
  cycle_stat_t pack;
  cycle_stat_t indcpa_rebuild_total;
} kyber_keygen_breakdown_t;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
#define PROFILE_SEPARATOR "----------------------------------------------------------------------------------------------\r\n"
/* Default benchmark rounds for stable UART-reported averages on this target. */
#define BENCH_ROUNDS 1000u
#define KYBER_DEC_SUCCESS 0
#define KEM_SCHEME_COL_WIDTH 12
#define KEM_CYCLES_COL_WIDTH 12
#define KEM_MISMATCH_COL_WIDTH 8
#define BENCH_RUN_LOCATION "STM32F407 MCU (Src/main.c)"
/* Simple coprime multipliers for deterministic, non-constant per-round/per-index byte patterns. */
#define DERAND_ROUND_MULTIPLIER 17u
#define DERAND_INDEX_MULTIPLIER 31u
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
uint8_t rx_buffer;
uint8_t cmd_flag = 0;
char cmd;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */
static void run_kem_comparison_benchmark(void);
static void enable_cycle_counter(void);
static void run_kyber_benchmark(uint32_t rounds,
                                uint64_t *keygen_total,
                                uint64_t *encaps_total,
                                uint64_t *decaps_total,
                                uint32_t *keygen_success_count,
                                uint32_t *encaps_success_count,
                                uint32_t *decaps_success_count,
                                uint32_t *error_count,
                                uint32_t *mismatch_count);
static void print_report_separator(void);
static void print_kyber_data_sizes(void);
static uint64_t safe_average(uint64_t total_cycles, uint32_t count);
static void print_kem_summary_row(const kem_summary_t *summary);
static void run_kyber_keygen_breakdown_benchmark(uint32_t rounds,
                                                 kyber_keygen_breakdown_t *breakdown,
                                                 uint32_t *error_count);
static void init_cycle_stat(cycle_stat_t *stat);
static void add_cycle_sample(cycle_stat_t *stat, uint32_t cycles);
static uint64_t average_cycle_stat(const cycle_stat_t *stat);
static void fill_deterministic_bytes(uint8_t *buf, uint32_t len, uint32_t round);
static void print_breakdown_row(const char *name, const cycle_stat_t *stat, uint64_t total_avg);
static void print_keygen_breakdown(const kyber_keygen_breakdown_t *breakdown);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
int __io_putchar(int ch)
{
  HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 100);
  return ch;
}

int fputc(int ch, FILE *f)
{
  /* UART stdout only: FILE parameter unused in embedded UART implementation. */
  (void)f;
  return __io_putchar(ch);
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
  if(huart->Instance == USART1)
  {
    cmd = rx_buffer;
    cmd_flag = 1;
    HAL_UART_Receive_IT(&huart1, &rx_buffer, 1);
  }
}

static void enable_cycle_counter(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;
}

static void run_kyber_benchmark(uint32_t rounds,
                                uint64_t *keygen_total,
                                uint64_t *encaps_total,
                                uint64_t *decaps_total,
                                uint32_t *keygen_success_count,
                                uint32_t *encaps_success_count,
                                uint32_t *decaps_success_count,
                                uint32_t *error_count,
                                uint32_t *mismatch_count)
{
  static uint8_t pk[pqcrystals_kyber512_ref_PUBLICKEYBYTES];
  static uint8_t sk[pqcrystals_kyber512_ref_SECRETKEYBYTES];
  static uint8_t ct[pqcrystals_kyber512_ref_CIPHERTEXTBYTES];
  static uint8_t ss1[pqcrystals_kyber512_ref_BYTES], ss2[pqcrystals_kyber512_ref_BYTES];
  uint32_t t0;
  uint32_t elapsed_cycles;
  int keygen_ret;
  int enc_ret;
  int dec_ret;

  *keygen_total = 0;
  *encaps_total = 0;
  *decaps_total = 0;
  *keygen_success_count = 0;
  *encaps_success_count = 0;
  *decaps_success_count = 0;
  *error_count = 0;
  *mismatch_count = 0;

  for(uint32_t round = 0; round < rounds; round++)
  {
    t0 = DWT->CYCCNT;
    keygen_ret = pqcrystals_kyber512_ref_keypair(pk, sk);
    elapsed_cycles = DWT->CYCCNT - t0;
    if(keygen_ret != 0) {
      (*error_count)++;
      continue;
    }
    *keygen_total += (uint64_t)elapsed_cycles;
    (*keygen_success_count)++;

    t0 = DWT->CYCCNT;
    enc_ret = pqcrystals_kyber512_ref_enc(ct, ss1, pk);
    elapsed_cycles = DWT->CYCCNT - t0;
    if(enc_ret != 0) {
      (*error_count)++;
      continue;
    }
    *encaps_total += (uint64_t)elapsed_cycles;
    (*encaps_success_count)++;

    t0 = DWT->CYCCNT;
    dec_ret = pqcrystals_kyber512_ref_dec(ss2, ct, sk);
    *decaps_total += (uint64_t)(DWT->CYCCNT - t0);
    (*decaps_success_count)++;

    if((dec_ret != KYBER_DEC_SUCCESS) || (memcmp(ss1, ss2, pqcrystals_kyber512_ref_BYTES) != 0)) {
      (*mismatch_count)++;
    }
  }
}

static void print_report_separator(void)
{
  printf("%s", PROFILE_SEPARATOR);
}

static void print_kyber_data_sizes(void)
{
  printf(">>> PART 0: Protocol Data Sizes (Serialized/Wire Format)\r\n");
  print_report_separator();
  printf("%-35s %-15s\r\n", "Component", "Size (Bytes)");
  print_report_separator();

  printf("[Kyber512] Public Key (pk):\r\n");
  printf("  %-33s %lu\r\n", "pqcrystals_kyber512_ref_PUBLICKEYBYTES", (unsigned long)pqcrystals_kyber512_ref_PUBLICKEYBYTES);

  printf("[Kyber512] Secret Key (sk):\r\n");
  printf("  %-33s %lu\r\n", "pqcrystals_kyber512_ref_SECRETKEYBYTES", (unsigned long)pqcrystals_kyber512_ref_SECRETKEYBYTES);

  printf("[Kyber512] Ciphertext (ct):\r\n");
  printf("  %-33s %lu\r\n", "pqcrystals_kyber512_ref_CIPHERTEXTBYTES", (unsigned long)pqcrystals_kyber512_ref_CIPHERTEXTBYTES);

  printf("[Kyber512] Shared Secret (ss):\r\n");
  printf("  %-33s %lu\r\n", "pqcrystals_kyber512_ref_BYTES", (unsigned long)pqcrystals_kyber512_ref_BYTES);

  print_report_separator();
  printf("\r\n");
}

static uint64_t safe_average(uint64_t total_cycles, uint32_t count)
{
  if(count == 0u) {
    return 0ULL;
  }
  return total_cycles / count;
}

static void print_kem_summary_row(const kem_summary_t *summary)
{
  printf("%-*s | %*llu | %*llu | %*llu | %*lu\r\n",
         KEM_SCHEME_COL_WIDTH,
         summary->name,
         KEM_CYCLES_COL_WIDTH,
         (unsigned long long)safe_average(summary->keygen_cycles, summary->keygen_success_count),
         KEM_CYCLES_COL_WIDTH,
         (unsigned long long)safe_average(summary->encaps_cycles, summary->encaps_success_count),
         KEM_CYCLES_COL_WIDTH,
         (unsigned long long)safe_average(summary->decaps_cycles, summary->decaps_success_count),
         KEM_MISMATCH_COL_WIDTH,
         (unsigned long)summary->mismatch_count);
}

static void init_cycle_stat(cycle_stat_t *stat)
{
  stat->total = 0ULL;
  stat->min = 0xFFFFFFFFu;
  stat->max = 0u;
  stat->count = 0u;
}

static void add_cycle_sample(cycle_stat_t *stat, uint32_t cycles)
{
  stat->total += (uint64_t)cycles;
  if(cycles < stat->min) {
    stat->min = cycles;
  }
  if(cycles > stat->max) {
    stat->max = cycles;
  }
  stat->count++;
}

static uint64_t average_cycle_stat(const cycle_stat_t *stat)
{
  if(stat->count == 0u) {
    return 0ULL;
  }
  return stat->total / stat->count;
}

static void fill_deterministic_bytes(uint8_t *buf, uint32_t len, uint32_t round)
{
  for(uint32_t i = 0; i < len; i++) {
    /* Mix round and index so derand input is repeatable but not trivially constant across rounds. */
    buf[i] = (uint8_t)((round * DERAND_ROUND_MULTIPLIER) + (i * DERAND_INDEX_MULTIPLIER) + (round >> 3));
  }
}

static void print_breakdown_row(const char *name, const cycle_stat_t *stat, uint64_t total_avg)
{
  uint64_t avg = average_cycle_stat(stat);
  uint64_t pct_x100 = (total_avg == 0ULL) ? 0ULL : ((avg * 10000ULL) / total_avg);
  printf("%-24s | %-14llu | %3llu.%02llu\r\n",
         name,
         (unsigned long long)avg,
         (unsigned long long)(pct_x100 / 100ULL),
         (unsigned long long)(pct_x100 % 100ULL));
}

static void run_kyber_keygen_breakdown_benchmark(uint32_t rounds,
                                                 kyber_keygen_breakdown_t *breakdown,
                                                 uint32_t *error_count)
{
  static uint8_t pk[pqcrystals_kyber512_ref_PUBLICKEYBYTES];
  static uint8_t sk[pqcrystals_kyber512_ref_SECRETKEYBYTES];
  static uint8_t coins64[2 * KYBER_SYMBYTES];
  static uint8_t coins32[KYBER_SYMBYTES];
  static uint8_t buf[2 * KYBER_SYMBYTES];
  static polyvec a[KYBER_K];
  static polyvec e;
  static polyvec pkpv;
  static polyvec skpv;
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
  uint8_t nonce;
  uint32_t t0;
  uint32_t tstart;

  init_cycle_stat(&breakdown->keypair_total);
  init_cycle_stat(&breakdown->keypair_derand_total);
  init_cycle_stat(&breakdown->rng);
  init_cycle_stat(&breakdown->indcpa_total);
  init_cycle_stat(&breakdown->kem_tail);
  init_cycle_stat(&breakdown->seed_expand);
  init_cycle_stat(&breakdown->gen_matrix);
  init_cycle_stat(&breakdown->sample);
  init_cycle_stat(&breakdown->ntt);
  init_cycle_stat(&breakdown->matvec);
  init_cycle_stat(&breakdown->add_reduce);
  init_cycle_stat(&breakdown->pack);
  init_cycle_stat(&breakdown->indcpa_rebuild_total);
  *error_count = 0u;

  for(uint32_t round = 0; round < rounds; round++) {
    t0 = DWT->CYCCNT;
    if(pqcrystals_kyber512_ref_keypair(pk, sk) != 0) {
      (*error_count)++;
      continue;
    }
    add_cycle_sample(&breakdown->keypair_total, DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    randombytes(coins64, 2 * KYBER_SYMBYTES);
    add_cycle_sample(&breakdown->rng, DWT->CYCCNT - t0);

    fill_deterministic_bytes(coins64, 2 * KYBER_SYMBYTES, round);
    tstart = DWT->CYCCNT;
    t0 = DWT->CYCCNT;
    indcpa_keypair_derand(pk, sk, coins64);
    add_cycle_sample(&breakdown->indcpa_total, DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins64 + KYBER_SYMBYTES, KYBER_SYMBYTES);
    add_cycle_sample(&breakdown->kem_tail, DWT->CYCCNT - t0);
    add_cycle_sample(&breakdown->keypair_derand_total, DWT->CYCCNT - tstart);

    fill_deterministic_bytes(coins32, KYBER_SYMBYTES, round);
    tstart = DWT->CYCCNT;
    memcpy(buf, coins32, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = KYBER_K;

    t0 = DWT->CYCCNT;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);
    add_cycle_sample(&breakdown->seed_expand, DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    gen_matrix(a, publicseed, 0);
    add_cycle_sample(&breakdown->gen_matrix, DWT->CYCCNT - t0);

    nonce = 0;
    t0 = DWT->CYCCNT;
    for(uint32_t i = 0; i < KYBER_K; i++) {
      poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    }
    for(uint32_t i = 0; i < KYBER_K; i++) {
      poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    }
    add_cycle_sample(&breakdown->sample, DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    polyvec_ntt(&skpv);
    polyvec_ntt(&e);
    add_cycle_sample(&breakdown->ntt, DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    for(uint32_t i = 0; i < KYBER_K; i++) {
      polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
      poly_tomont(&pkpv.vec[i]);
    }
    add_cycle_sample(&breakdown->matvec, DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);
    add_cycle_sample(&breakdown->add_reduce, DWT->CYCCNT - t0);

    t0 = DWT->CYCCNT;
    polyvec_tobytes(sk, &skpv);
    polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES);
    add_cycle_sample(&breakdown->pack, DWT->CYCCNT - t0);
    add_cycle_sample(&breakdown->indcpa_rebuild_total, DWT->CYCCNT - tstart);
  }
}

static void print_keygen_breakdown(const kyber_keygen_breakdown_t *breakdown)
{
  uint64_t derand_avg = average_cycle_stat(&breakdown->keypair_derand_total);
  uint64_t indcpa_avg = average_cycle_stat(&breakdown->indcpa_total);
  uint64_t rebuild_avg = average_cycle_stat(&breakdown->indcpa_rebuild_total);
  uint64_t rng_avg = average_cycle_stat(&breakdown->rng);
  uint64_t keypair_avg = average_cycle_stat(&breakdown->keypair_total);

  printf(">>> PART 1: Kyber512 KeyGen Breakdown (Cycles)\r\n");
  print_report_separator();
  printf("Baseline keypair (api): avg=%llu, min=%lu, max=%lu\r\n",
         (unsigned long long)keypair_avg,
         (unsigned long)breakdown->keypair_total.min,
         (unsigned long)breakdown->keypair_total.max);
  printf("RNG(randombytes 64B): avg=%llu\r\n", (unsigned long long)rng_avg);
  printf("keypair_derand (reconstructed): avg=%llu, min=%lu, max=%lu\r\n",
         (unsigned long long)derand_avg,
         (unsigned long)breakdown->keypair_derand_total.min,
         (unsigned long)breakdown->keypair_derand_total.max);
  print_report_separator();
  printf("%-24s | %-14s | %-12s\r\n", "Stage", "Avg Cycles", "Share(%)");
  print_report_separator();
  print_breakdown_row("indcpa_total", &breakdown->indcpa_total, derand_avg);
  print_breakdown_row("kem_tail", &breakdown->kem_tail, derand_avg);
  print_report_separator();
  print_breakdown_row("seed_expand(hash_g)", &breakdown->seed_expand, rebuild_avg);
  print_breakdown_row("gen_matrix(A)", &breakdown->gen_matrix, rebuild_avg);
  print_breakdown_row("sample(s,e)", &breakdown->sample, rebuild_avg);
  print_breakdown_row("ntt(s,e)", &breakdown->ntt, rebuild_avg);
  print_breakdown_row("matvec+tomont", &breakdown->matvec, rebuild_avg);
  print_breakdown_row("add+reduce", &breakdown->add_reduce, rebuild_avg);
  print_breakdown_row("pack(pk,sk)", &breakdown->pack, rebuild_avg);
  print_breakdown_row("rebuild_total", &breakdown->indcpa_rebuild_total, rebuild_avg);
  print_report_separator();
  printf("indcpa_total avg = %llu, rebuild_total avg = %llu\r\n",
         (unsigned long long)indcpa_avg,
         (unsigned long long)rebuild_avg);
  printf("\r\n");
}

static void run_kem_comparison_benchmark(void)
{
  kem_summary_t kyber_summary = {
    .name = "Kyber512",
    .keygen_cycles = 0,
    .encaps_cycles = 0,
    .decaps_cycles = 0,
    .keygen_success_count = 0,
    .encaps_success_count = 0,
    .decaps_success_count = 0,
    .error_count = 0,
    .mismatch_count = 0
  };
  kyber_keygen_breakdown_t keygen_breakdown;
  uint32_t keygen_breakdown_error_count = 0u;

  printf("\r\n=== Kyber512 Comprehensive Benchmark Report ===\r\n");
  printf("Run Location: %s\r\n", BENCH_RUN_LOCATION);
  printf("Rounds: %lu\r\n\r\n", (unsigned long)BENCH_ROUNDS);
  print_kyber_data_sizes();

  enable_cycle_counter();

  run_kyber_benchmark(BENCH_ROUNDS,
                      &kyber_summary.keygen_cycles,
                      &kyber_summary.encaps_cycles,
                      &kyber_summary.decaps_cycles,
                      &kyber_summary.keygen_success_count,
                      &kyber_summary.encaps_success_count,
                      &kyber_summary.decaps_success_count,
                      &kyber_summary.error_count,
                      &kyber_summary.mismatch_count);
  run_kyber_keygen_breakdown_benchmark(BENCH_ROUNDS,
                                       &keygen_breakdown,
                                       &keygen_breakdown_error_count);

  print_keygen_breakdown(&keygen_breakdown);

  printf(">>> PART 2: KEM Full Flow Summary (IND-CCA2)\r\n");
  print_report_separator();
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
  print_report_separator();
  print_kem_summary_row(&kyber_summary);
  print_report_separator();
  printf("KEM operation error count: %lu\r\n", (unsigned long)kyber_summary.error_count);
  printf("KeyGen breakdown error count: %lu\r\n", (unsigned long)keygen_breakdown_error_count);
  printf("KEM shared-secret mismatch count: %lu\r\n", (unsigned long)kyber_summary.mismatch_count);
  printf("[FINAL] Benchmark complete.\r\n\r\n");
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  HAL_Init();
  SystemClock_Config();

  MX_GPIO_Init();
  MX_USART1_UART_Init();
  MX_RNG_Init();

  HAL_UART_Receive_IT(&huart1, &rx_buffer, 1);

  /* USER CODE BEGIN 2 */
  printf("=========================\r\n");
  printf("  KYBER TEST SYSTEM READY\r\n");
  printf("=========================\r\n");
  printf("RUN LOCATION: %s\r\n", BENCH_RUN_LOCATION);
  printf("TEST ROUNDS: %lu\r\n", (unsigned long)BENCH_ROUNDS);
  printf("CMD: C=RUN KYBER512 COMPREHENSIVE REPORT (%lu rounds)\r\n", (unsigned long)BENCH_ROUNDS);
  printf("BUILD MODE: KYBER-ONLY BENCHMARK\r\n");
  printf("=========================\r\n");
  /* USER CODE END 2 */

  while (1)
  {
    if(cmd_flag == 1)
    {
      cmd_flag = 0;

      if(cmd == 'C' || cmd == 'c')
      {
        run_kem_comparison_benchmark();
      }
      else
      {
        printf("ONLY CMD 'C' IS ENABLED\r\n\r\n");
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

  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

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
