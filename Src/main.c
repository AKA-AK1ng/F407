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
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

typedef struct {
  const char *name;
  uint64_t keygen_cycles;
  uint64_t encaps_cycles;
  uint64_t decaps_cycles;
  uint32_t mismatch_count;
} kem_summary_t;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
#define PROFILE_SEPARATOR "----------------------------------------------------------------------------------------------\r\n"
#define BENCH_ROUNDS 1000u
#define KEM_SCHEME_COL_WIDTH 12
#define KEM_CYCLES_COL_WIDTH 12
#define KEM_MISMATCH_COL_WIDTH 8
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
static void run_kyber_benchmark(uint32_t rounds, uint64_t *keygen_total, uint64_t *encaps_total, uint64_t *decaps_total, uint32_t *mismatch_count);
static void print_kem_summary_row(const kem_summary_t *summary, uint32_t rounds);
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
  if(rounds == 0u) {
    return;
  }

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

static void run_kem_comparison_benchmark(void)
{
  kem_summary_t kyber_summary = {"Kyber512", 0, 0, 0, 0};

  printf("\r\n=== Kyber512 Cycles Quick Benchmark (%lu rounds) ===\r\n", (unsigned long)BENCH_ROUNDS);
  enable_cycle_counter();

  run_kyber_benchmark(BENCH_ROUNDS,
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
  print_kem_summary_row(&kyber_summary, BENCH_ROUNDS);
  printf("%s\r\n", PROFILE_SEPARATOR);
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
  printf("CMD: C=RUN KYBER512 CYCLE TABLE (%lu rounds)\r\n", (unsigned long)BENCH_ROUNDS);
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
