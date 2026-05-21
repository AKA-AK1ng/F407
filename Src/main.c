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
#include "../ref_viper/api.h"
#include "../ref_viper/viper.h"
#include "../ref_viper/viper_arith.h"
#include "stm32f4xx.h"
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
#define VIPER_BENCH_ROUNDS 100u
#define VIPER_BENCH_PROGRESS_STEP 100u
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
// 串口接收变量
volatile uint8_t rx_buffer;        // 单字节接收缓存
volatile uint8_t cmd_flag = 0;     // 指令有效标志
volatile char cmd;                 // 存储接收到的指令

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */
static void run_viper_breakdown(void);

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
  uint64_t pke_keygen;
  uint64_t pke_encrypt;
  uint64_t pke_decrypt;
  uint32_t pke_mismatch_count;
  uint64_t kem_keygen;
  uint64_t kem_encaps;
  uint64_t kem_decaps;
  uint32_t kem_mismatch_count;
} viper_run_totals_t;

static uint64_t viper_bench_avg(uint64_t total)
{
  return total / VIPER_BENCH_ROUNDS;
}

static uint64_t viper_bench_avg_per_call(uint64_t total, uint32_t count)
{
  if (count == 0u) return 0u;
  return total / (uint64_t)count;
}

static void dwt_enable_cycle_counter(void)
{
  /* Enable trace and DWT cycle counter */
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

static uint64_t dwt_now_cycles(void)
{
  return (uint64_t)DWT->CYCCNT;
}

static void measure_viper_round(viper_run_totals_t *totals)
{
  uint64_t t0;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss1[CRYPTO_BYTES];
  uint8_t ss2[CRYPTO_BYTES];
  uint8_t skpke[VIPER_SECRETKEY_PKE_BYTES];
  uint8_t pk_pke[VIPER_PUBLICKEYBYTES];
  uint8_t ct_pke[VIPER_CIPHERTEXTBYTES];
  uint8_t msg_in[32];
  uint8_t msg_out[32];
  uint8_t rho[32];
  uint8_t sseed[32];
  uint8_t omega[64];
  int kem_ok;

  random_bytes(rho, sizeof(rho));
  random_bytes(sseed, sizeof(sseed));

  random_bytes(msg_in, sizeof(msg_in));
  random_bytes(omega, sizeof(omega));

  t0 = dwt_now_cycles();
  viper_pke_keypair(pk_pke, skpke, rho, sseed);
  totals->pke_keygen += (dwt_now_cycles() - t0);

  t0 = dwt_now_cycles();
  viper_pke_enc(ct_pke, pk_pke, msg_in, omega);
  totals->pke_encrypt += (dwt_now_cycles() - t0);

  t0 = dwt_now_cycles();
  viper_pke_dec(msg_out, skpke, ct_pke);
  totals->pke_decrypt += (dwt_now_cycles() - t0);

  if(memcmp(msg_in, msg_out, sizeof(msg_in)) != 0) {
    totals->pke_mismatch_count++;
  }

  t0 = dwt_now_cycles();
  kem_ok = (crypto_kem_keypair(pk, sk) == 0);
  totals->kem_keygen += (dwt_now_cycles() - t0);

  t0 = dwt_now_cycles();
  kem_ok = kem_ok && (crypto_kem_enc(ct, ss1, pk) == 0);
  totals->kem_encaps += (dwt_now_cycles() - t0);

  t0 = dwt_now_cycles();
  kem_ok = kem_ok && (crypto_kem_dec(ss2, ct, sk) == 0);
  totals->kem_decaps += (dwt_now_cycles() - t0);

  if((!kem_ok) || (memcmp(ss1, ss2, CRYPTO_BYTES) != 0)) {
    totals->kem_mismatch_count++;
  }
}

static void run_viper_breakdown(void)
{
  viper_run_totals_t totals = {0};
  viper_bench_totals_t bench = {0};

  printf("\r\n=== Viper Breakdown Benchmark (STM32 Scalar) ===\r\n");
  printf("VIPER_LEVEL=%d\r\n", VIPER_LEVEL);
  viper_backend_report(stdout);

  viper_bench_reset();
  for(uint32_t round = 0; round < VIPER_BENCH_ROUNDS; round++)
  {
    measure_viper_round(&totals);
    if(((round + 1u) % VIPER_BENCH_PROGRESS_STEP) == 0u) {
      printf("VIPER BENCH PROGRESS: %lu/%lu\r\n",
             (unsigned long)(round + 1u),
             (unsigned long)VIPER_BENCH_ROUNDS);
    }
  }
  viper_bench_get(&bench);

  printf("\r\n%s", PROFILE_SEPARATOR);
  printf(" Viper Breakdown (Avg, %lu rounds)\r\n", (unsigned long)VIPER_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
    printf("Mul: %lu (per-call %lu)\r\n",
      (unsigned long)viper_bench_avg(bench.mul),
      (unsigned long)viper_bench_avg_per_call(bench.mul, bench.mul_count));
    printf("A*s: %lu (per-call %lu)\r\n",
      (unsigned long)viper_bench_avg(bench.as),
      (unsigned long)viper_bench_avg_per_call(bench.as, bench.as_count));
    printf("A^T*r: %lu (per-call %lu)\r\n",
      (unsigned long)viper_bench_avg(bench.atr),
      (unsigned long)viper_bench_avg_per_call(bench.atr, bench.atr_count));
    printf("b^T*r: %lu (per-call %lu)\r\n",
      (unsigned long)viper_bench_avg(bench.btr),
      (unsigned long)viper_bench_avg_per_call(bench.btr, bench.btr_count));
    printf("s^T*u: %lu (per-call %lu)\r\n",
      (unsigned long)viper_bench_avg(bench.stu),
      (unsigned long)viper_bench_avg_per_call(bench.stu, bench.stu_count));

  printf("\r\n%s", PROFILE_SEPARATOR);
  printf(" Viper PKE (Avg, %lu rounds)\r\n", (unsigned long)VIPER_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("PKE KeyGen: %lu\r\n", (unsigned long)viper_bench_avg(totals.pke_keygen));
  printf("PKE Encrypt: %lu\r\n", (unsigned long)viper_bench_avg(totals.pke_encrypt));
  printf("PKE Decrypt: %lu\r\n", (unsigned long)viper_bench_avg(totals.pke_decrypt));
  printf("PKE mismatch count: %lu\r\n", (unsigned long)totals.pke_mismatch_count);
  printf("\r\n%s", PROFILE_SEPARATOR);
  printf(" Viper KEM (Avg, %lu rounds)\r\n", (unsigned long)VIPER_BENCH_ROUNDS);
  printf("%s", PROFILE_SEPARATOR);
  printf("KEM KeyGen: %lu\r\n", (unsigned long)viper_bench_avg(totals.kem_keygen));
  printf("KEM Encaps: %lu\r\n", (unsigned long)viper_bench_avg(totals.kem_encaps));
  printf("KEM Decaps: %lu\r\n", (unsigned long)viper_bench_avg(totals.kem_decaps));
  printf("KEM mismatch count: %lu\r\n", (unsigned long)totals.kem_mismatch_count);
  printf("%s", PROFILE_SEPARATOR);
  printf("[FINAL] Viper breakdown complete.\r\n\r\n");
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
  // 启用 DWT 计数器用于周期计时
  dwt_enable_cycle_counter();

  // 开机提示
  printf("=========================\r\n");
  printf("  VIPER TEST SYSTEM READY\r\n");
  printf("=========================\r\n");
  printf("CMD: V=RUN VIPER BREAKDOWN (%lu rounds)\r\n", (unsigned long)VIPER_BENCH_ROUNDS);
  printf("=========================\r\n");
  /* USER CODE END 2 */

  // 4. 主循环
  while (1)
  {
    if(cmd_flag == 1)
    {
      cmd_flag = 0;

      // ====================== 修改点1：添加命令回传 ======================
      printf("Received Command: [%c]\r\n", cmd);

      if(cmd == 'V' || cmd == 'v')
      {
        run_viper_breakdown();
      }
      else
      {
        printf("ONLY CMD 'V' IS ENABLED\r\n\r\n");
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
  RCC_OscInitStruct.PLL.PLLN = 72;       // 从168改为72
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV6; // 从DIV2改为DIV6
  RCC_OscInitStruct.PLL.PLLQ = 3;        // 不用USB可保留，用USB需改为3，改回了3匹配pqm4
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;   // HCLK=24MHz
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;    // PCLK1=24MHz，改为了2匹配pqm4
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;    // PCLK2=24MHz

  // ====================== 修改点2：修复闪存等待周期（致命错误） ======================
  // 原代码：FLASH_LATENCY_5（168MHz用），24MHz必须用 LATENCY_0
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
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
