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
#include "led.h"
#include "stdio.h"  // 用于printf
#include "ctype.h"
#include "stdlib.h"
#include "string.h"
#include "random.h"
#include "params.h"
#include "xof.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
// 串口接收变量（volatile：在ISR中修改、在主循环中读取，防止编译器优化导致主循环读不到变化）
volatile uint8_t rx_buffer;        // 单字节接收缓存
volatile uint8_t cmd_flag = 0;     // 指令有效标志（ISR置1，主循环清0）
volatile char cmd;                 // 存储接收到的指令

// RNG随机数变量
uint32_t random_num;      // 存储32位硬件随机数

// 命令处理工作区（避免在主循环分支里创建大栈变量导致潜在栈溢出）
static poly cmd_poly;

// XOF测试工作区：提前按mlwq中expand的参数路径预留，避免命令分支里大栈分配
static poly_matrix xof_A;
static poly_vec xof_d_pk;
static poly_vec xof_d_u;
static uint8_t xof_seed_A[SEEDBYTES];
static uint8_t xof_seed_d[SEEDBYTES];
static uint8_t xof_seed_ct[SEEDBYTES];
static uint8_t xof_seed_d_pk_ext[SEEDBYTES + 1];
static uint8_t xof_seed_d_u_ext[SEEDBYTES + 1];
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */

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
    // LED1翻转：每收到1字节闪烁一次，硬件可见的接收指示
    LED1_Toggle();

    // 读取接收到的指令
    cmd = rx_buffer;
    // 置位指令标志（主循环中会检测并处理）
    cmd_flag = 1;
    // 重新开启接收（无限次指令）
    HAL_UART_Receive_IT(&huart1, (uint8_t *)&rx_buffer, 1);
  }
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
  HAL_UART_Receive_IT(&huart1, (uint8_t *)&rx_buffer, 1);

  /* USER CODE BEGIN 2 */
  // 开机提示
  printf("=========================\r\n");
  printf("  RNG TEST SYSTEM READY\r\n");
  printf("=========================\r\n");
  printf("USART1: PA9(TX) PA10(RX)\r\n");
  printf("115200 8N1, no flow ctrl\r\n");
  printf("-------------------------\r\n");
  printf("CMD: R = random_bytes(16)\r\n");
  printf("CMD: P = poly uniform\r\n");
  printf("CMD: E = poly eta (CBD)\r\n");
  printf("CMD: X = all mlwq expand(xof)\r\n");
  printf("=========================\r\n");
  /* USER CODE END 2 */

  // 4. 主循环
  while (1)
    {
      if(cmd_flag == 1)
      {
        cmd_flag = 0;

        // 调试：打印收到的原始字节（十六进制）及可打印字符，方便排查是否进入主循环
        printf("RX: 0x%02X ('%c')\r\n", (uint8_t)cmd, isprint((unsigned char)cmd) ? cmd : '.');

        if(cmd == 'R' || cmd == 'r')
        {
          // --------------------------
          // 测试 random_bytes
          // --------------------------
          uint8_t rnd_buf[16];
          random_bytes(rnd_buf, 16);

          printf("RANDOM 16 BYTES:\r\n");
          for(int i=0; i<16; i++)
          {
            printf("%02X ", rnd_buf[i]);
          }
          printf("\r\n\r\n");
        }
        else if(cmd == 'P' || cmd == 'p')
        {
          // --------------------------
          // 测试随机多项式 uniform
          // --------------------------
          random_poly_uniform(&cmd_poly);

          printf("POLY UNIFORM (first 10 coeffs):\r\n");
          for(int i=0; i<10; i++)
          {
            printf("%d ", cmd_poly.coeffs[i]);
          }
          printf("\r\n\r\n");
        }
        else if(cmd == 'E' || cmd == 'e')
        {
          // --------------------------
          // 测试 CBD eta 随机多项式
          // --------------------------
          random_poly_eta(&cmd_poly);

          printf("POLY ETA (CBD, first 10):\r\n");
          for(int i=0; i<10; i++)
          {
            printf("%d ", cmd_poly.coeffs[i]);
          }
          printf("\r\n\r\n");
        }
        else if(cmd == 'X' || cmd == 'x')
        {
          // --------------------------
          // 测试XOF：一次性覆盖mlwq里所有expand入口参数
          // 1) A:    expand_matrix(seed_A)
          // 2) d_pk: expand_poly_vec(seed_d||0xFF, q/P_PK)
          // 3) d_u:  expand_poly_vec(seed_ct||10, q/P_U)
          // --------------------------
          random_bytes(xof_seed_A, SEEDBYTES);
          random_bytes(xof_seed_d, SEEDBYTES);
          random_bytes(xof_seed_ct, SEEDBYTES);

          memcpy(xof_seed_d_pk_ext, xof_seed_d, SEEDBYTES);
          xof_seed_d_pk_ext[SEEDBYTES] = 0xFF;
          memcpy(xof_seed_d_u_ext, xof_seed_ct, SEEDBYTES);
          xof_seed_d_u_ext[SEEDBYTES] = 10;

          ref_xof_expand_matrix(&xof_A, xof_seed_A);
          ref_xof_expand_poly_vec(&xof_d_pk, xof_seed_d_pk_ext, MLWQ_Q / P_PK);
          ref_xof_expand_poly_vec(&xof_d_u, xof_seed_d_u_ext, MLWQ_Q / P_U);

          printf("XOF ALL EXPAND DONE\r\n");
          printf("A[0][0] first 8: ");
          for(int i=0; i<8; i++) printf("%d ", xof_A.row[0].vec[0].coeffs[i]);
          printf("\r\n");

          printf("d_pk[0] first 8: ");
          for(int i=0; i<8; i++) printf("%d ", xof_d_pk.vec[0].coeffs[i]);
          printf("\r\n");

          printf("d_u[0] first 8: ");
          for(int i=0; i<8; i++) printf("%d ", xof_d_u.vec[0].coeffs[i]);
          printf("\r\n");

          printf("WS bytes: A=%lu d_pk=%lu d_u=%lu total=%lu\r\n\r\n",
                 (unsigned long)sizeof(xof_A),
                 (unsigned long)sizeof(xof_d_pk),
                 (unsigned long)sizeof(xof_d_u),
                 (unsigned long)(sizeof(xof_A) + sizeof(xof_d_pk) + sizeof(xof_d_u)));
        }
        else
        {
          printf("INVALID CMD\r\n\r\n");
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
