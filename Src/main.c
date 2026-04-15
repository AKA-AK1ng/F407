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
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
#define DITHER_DOMAIN_SEPARATOR 0xFFu
#define PROFILE_SEPARATOR "----------------------------------------------------------------------------------------------\r\n"
#define MLWQ_BENCH_ROUNDS 1000u
#define MLWQ_BENCH_PROGRESS_STEP 100u
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
  uint64_t enc_arith_u;
  uint64_t enc_arith_v;
  uint64_t dec_deq;
  uint64_t dec_sTu;
  uint64_t dec_sub;
  uint64_t dec_decode;
  uint32_t mismatch_count;
} mlwq_bench_totals_t;

static void mlwq_bench_measure_round(mlwq_bench_totals_t *totals)
{
  /* 全部 static，避免大对象压栈 */
  static mlwq_pk pk_prof;
  static mlwq_sk sk_prof;
  static mlwq_ciphertext ct_prof;

  static poly_matrix A_prof, At_prof;
  static poly_vec As_prof, d_pk_prof, r_prof, Atr_prof, b_deq_prof, u_deq_prof;
  static poly v_val_prof, m_poly_prof, v_final_prof, v_deq_prof, s_t_u_prof, diff_prof, zero_poly;
  static uint8_t seed_A[SEEDBYTES], seed_d[SEEDBYTES], seed_ct[SEEDBYTES], seed_s[SEEDBYTES];
  static uint8_t msg_in[32], msg_out[32], d_seed[33];

  uint32_t t0;

  for(int i = 0; i < MLWQ_N; i++) {
    zero_poly.coeffs[i] = 0;
  }

  random_bytes(seed_A, SEEDBYTES);
  random_bytes(seed_d, SEEDBYTES);
  random_bytes(seed_ct, SEEDBYTES);
  random_bytes(msg_in, sizeof(msg_in));
  random_bytes(seed_s, SEEDBYTES);

  // KeyGen breakdown
  t0 = DWT->CYCCNT;
  ref_xof_expand_matrix(&A_prof, seed_A);
  totals->key_genA += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_getnoise_eta1(&sk_prof.s.vec[i], seed_s, (uint8_t)i);
  }
  totals->key_sample_s += (uint64_t)(DWT->CYCCNT - t0);

  for(int i = 0; i < SEEDBYTES; i++) d_seed[i] = seed_d[i];
  d_seed[SEEDBYTES] = DITHER_DOMAIN_SEPARATOR;
  t0 = DWT->CYCCNT;
  ref_xof_expand_poly_vec(&d_pk_prof, d_seed, MLWQ_Q / P_PK);
  totals->key_gendither += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  ref_poly_matrix_vec_mul(&As_prof, &A_prof, &sk_prof.s);
  totals->key_arith_as += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_quantize(&pk_prof.b_q.vec[i], &As_prof.vec[i], &d_pk_prof.vec[i], P_PK);
  }
  totals->key_quantize += (uint64_t)(DWT->CYCCNT - t0);

  for(int i = 0; i < SEEDBYTES; i++) {
    pk_prof.seed_A[i] = seed_A[i];
    pk_prof.seed_d[i] = seed_d[i];
  }

  // Encrypt arithmetic breakdown
  ref_xof_expand_matrix(&A_prof, pk_prof.seed_A);
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_getnoise_eta1(&r_prof.vec[i], seed_ct, (uint8_t)i);
    ref_poly_dequantize(&b_deq_prof.vec[i], &pk_prof.b_q.vec[i], P_PK);
  }
  for(int i = 0; i < MLWQ_K; i++) {
    for(int j = 0; j < MLWQ_K; j++) {
      At_prof.row[i].vec[j] = A_prof.row[j].vec[i];
    }
  }

  t0 = DWT->CYCCNT;
  ref_poly_matrix_vec_mul(&Atr_prof, &At_prof, &r_prof);
  totals->enc_arith_u += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  ref_poly_vec_transpose_mul(&v_val_prof, &b_deq_prof, &r_prof);
  totals->enc_arith_v += (uint64_t)(DWT->CYCCNT - t0);

  // 构造可解密样本（不计入 breakdown）
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_quantize(&ct_prof.u.vec[i], &Atr_prof.vec[i], &zero_poly, P_U);
  }
  ref_poly_msg_encode(&m_poly_prof, msg_in);
  ref_poly_add(&v_final_prof, &v_val_prof, &m_poly_prof);
  ref_poly_quantize(&ct_prof.v, &v_final_prof, &zero_poly, P_V);

  // Decrypt breakdown
  t0 = DWT->CYCCNT;
  for(int i = 0; i < MLWQ_K; i++) {
    ref_poly_dequantize(&u_deq_prof.vec[i], &ct_prof.u.vec[i], P_U);
  }
  ref_poly_dequantize(&v_deq_prof, &ct_prof.v, P_V);
  totals->dec_deq += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  ref_poly_vec_transpose_mul(&s_t_u_prof, &sk_prof.s, &u_deq_prof);
  totals->dec_sTu += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  ref_poly_sub(&diff_prof, &v_deq_prof, &s_t_u_prof);
  totals->dec_sub += (uint64_t)(DWT->CYCCNT - t0);

  t0 = DWT->CYCCNT;
  ref_poly_msg_decode(msg_out, &diff_prof);
  totals->dec_decode += (uint64_t)(DWT->CYCCNT - t0);

  if(memcmp(msg_in, msg_out, sizeof(msg_in)) != 0) {
    totals->mismatch_count++;
  }
}

static void run_mlwq_benchmark(void)
{
  mlwq_bench_totals_t totals = {0};
  uint64_t sum_dec_arith_vsu;

  printf("MLWQ BENCH START (%lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("TEST POINTS: [K1]GenMatrix [K2]Sample [K3]GenDither [K4]Arith(A*s) [K5]Quantize ");
  printf("[E1]Arith(u) [E2]Arith(v) [D1]DeQuant [D2]Arith(v-su) [D3]Decode\r\n");

  /* 启用 DWT 周期计数器 */
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;

  for(uint32_t round = 0; round < MLWQ_BENCH_ROUNDS; round++)
  {
    mlwq_bench_measure_round(&totals);
    if(((round + 1u) % MLWQ_BENCH_PROGRESS_STEP) == 0u) {
      printf("BENCH PROGRESS: %lu/%lu\r\n",
             (unsigned long)(round + 1u),
             (unsigned long)MLWQ_BENCH_ROUNDS);
    }
  }

  sum_dec_arith_vsu = totals.dec_sTu + totals.dec_sub;

  printf("%s", PROFILE_SEPARATOR);
  printf(" PKE KeyGen Breakdown (Avg, %lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("GenMatrix (A): %lu\r\n", (unsigned long)(totals.key_genA / MLWQ_BENCH_ROUNDS));
  printf("Sample (s): %lu\r\n", (unsigned long)(totals.key_sample_s / MLWQ_BENCH_ROUNDS));
  printf("GenDither: %lu\r\n", (unsigned long)(totals.key_gendither / MLWQ_BENCH_ROUNDS));
  printf("Arith (A*s): %lu\r\n", (unsigned long)(totals.key_arith_as / MLWQ_BENCH_ROUNDS));
  printf("Quantize: %lu\r\n", (unsigned long)(totals.key_quantize / MLWQ_BENCH_ROUNDS));

  printf("%s", PROFILE_SEPARATOR);
  printf(" PKE Encrypt Breakdown (Avg, %lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("Arith (u): %lu\r\n", (unsigned long)(totals.enc_arith_u / MLWQ_BENCH_ROUNDS));
  printf("Arith (v): %lu\r\n", (unsigned long)(totals.enc_arith_v / MLWQ_BENCH_ROUNDS));

  printf("%s", PROFILE_SEPARATOR);
  printf(" PKE Decrypt Breakdown (Avg, %lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("DeQuantize: %lu\r\n", (unsigned long)(totals.dec_deq / MLWQ_BENCH_ROUNDS));
  printf("Arith (v-su): %lu (sTu=%lu sub=%lu)\r\n",
         (unsigned long)(sum_dec_arith_vsu / MLWQ_BENCH_ROUNDS),
         (unsigned long)(totals.dec_sTu / MLWQ_BENCH_ROUNDS),
         (unsigned long)(totals.dec_sub / MLWQ_BENCH_ROUNDS));
  printf("Decode: %lu\r\n", (unsigned long)(totals.dec_decode / MLWQ_BENCH_ROUNDS));
  printf("Decode mismatch count: %lu\r\n\r\n", (unsigned long)totals.mismatch_count);
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
  printf("  MLWQ BENCH SYSTEM READY\r\n");
  printf("=========================\r\n");
  printf("CMD: M=RUN MLWQ BENCHMARK (%lu rounds)\r\n", (unsigned long)MLWQ_BENCH_ROUNDS);
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
      else
      {
        printf("ONLY CMD 'M' IS ENABLED\r\n\r\n");
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
  RCC_OscInitStruct.PLL.PLLN = 72;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 3;
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
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
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
