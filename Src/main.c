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
#include "random.h"
#include "params.h"
/* NTT profile 所需头文件 (需确保 ref/ 目录在工程 include path 中) */
#include "../ref/ntt.h"
#include "../ref/reduce.h"
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
/* 将 int 系数归约到 [0, Q) 区间，用于模 Q 比较 */
#define COEFF_MOD_Q(x) (((int)(x) % MLWQ_Q + MLWQ_Q) % MLWQ_Q)
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
// 串口接收变量
uint8_t rx_buffer;        // 单字节接收缓存
uint8_t cmd_flag = 0;     // 指令有效标志
char cmd;                 // 存储接收到的指令

// RNG随机数变量
uint32_t random_num;      // 存储32位硬件随机数
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
    // 读取接收到的指令
    cmd = rx_buffer;
    // 置位指令标志
    cmd_flag = 1;
    // 重新开启接收（无限次指令）
    HAL_UART_Receive_IT(&huart1, &rx_buffer, 1);
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
  HAL_UART_Receive_IT(&huart1, &rx_buffer, 1);

  /* USER CODE BEGIN 2 */
  // 开机提示
  printf("=========================\r\n");
  printf("  RNG TEST SYSTEM READY\r\n");
  printf("=========================\r\n");
  printf("CMD: R=PRINT RANDOM\r\n");
  printf("CMD: L=RANDOM+LED FLASH\r\n");
  printf("CMD: P=POLY UNIFORM\r\n");
  printf("CMD: E=POLY ETA(CBD)\r\n");
  printf("CMD: T=POLY+NTT PROFILE\r\n");
  printf("CMD: M=MLWQ CYCLE BREAKDOWN\r\n");
  printf("=========================\r\n");
  /* USER CODE END 2 */

  // 4. 主循环
  while (1)
    {
      if(cmd_flag == 1)
      {
        cmd_flag = 0;

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
          poly p;
          random_poly_uniform(&p);

          printf("POLY UNIFORM (first 10 coeffs):\r\n");
          for(int i=0; i<10; i++)
          {
            printf("%d ", p.coeffs[i]);
          }
          printf("\r\n\r\n");
        }
        else if(cmd == 'E' || cmd == 'e')
        {
          // --------------------------
          // 测试 CBD eta 随机多项式
          // --------------------------
          poly p;
          random_poly_eta(&p);

          printf("POLY ETA (CBD, first 10):\r\n");
          for(int i=0; i<10; i++)
          {
            printf("%d ", p.coeffs[i]);
          }
          printf("\r\n\r\n");
        }
        else if(cmd == 'T' || cmd == 't')
        {
          // ---------------------------------------------------------------
          // POLY+NTT PROFILE
          // 使用 DWT CYCCNT (Cortex-M4) 计算各操作 cycle 数。
          // 多项式全部声明为 static，避免压栈导致 HardFault。
          // ---------------------------------------------------------------
          printf("POLY+NTT PROFILE\r\n");

          /* 启用 DWT 周期计数器 */
          CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
          DWT->CYCCNT = 0;
          DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;

          /* 工作区：全部 static，避免压栈导致 HardFault */
          static poly a_poly, b_poly, add_poly, sub_poly, rt_poly;
          static poly v_prof, s_t_u_prof, diff_prof;
          static poly_vec s_prof, u_prof, as_prof;
          static poly_matrix A_prof;
          static uint8_t seed_A_prof[SEEDBYTES];
          static int16_t saved_coeffs[MLWQ_N]; /* NTT 预测试原始系数 */

          /* ---- NTT 自检 ------------------------------------------------
           * 不变式：invntt(ntt(a))[i] = a[i] * R  (mod Q)，R = 2^16
           * 因此 montgomery_reduce(invntt(ntt(a))[i]) = a[i]  (mod Q)
           * 运行 10 组随机向量，全部通过才报告 PASS。
           * ---------------------------------------------------------------- */
          {
            int pass = 1;
            for(int trial = 0; trial < 10; trial++)
            {
              int ok = 1;
              random_poly_uniform(&rt_poly);

              /* 保存原始系数 */
              for(int i = 0; i < MLWQ_N; i++)
                saved_coeffs[i] = rt_poly.coeffs[i];

              /* 正向 NTT 再逆向 NTT */
              ntt(rt_poly.coeffs);
              invntt(rt_poly.coeffs);

              /* 比较：从 Montgomery 域还原后应与原始值同余 (mod Q) */
              for(int i = 0; i < MLWQ_N; i++)
              {
                int16_t got = montgomery_reduce((int32_t)rt_poly.coeffs[i]);
                if(COEFF_MOD_Q(saved_coeffs[i]) != COEFF_MOD_Q(got)) { ok = 0; break; }
              }
              if(!ok) { pass = 0; break; }
            }
            printf("NTT pre-test (ntt->invntt): %s\r\n", pass ? "PASS" : "FAIL");
          }

          /* ---- 生成随机多项式用于 cycle profile ---- */
          random_poly_uniform(&a_poly);
          random_poly_uniform(&b_poly);

          /* ---- 生成 A,s,u,v 用于 Arith cycle profile ---- */
          random_bytes(seed_A_prof, SEEDBYTES);
          ref_xof_expand_matrix(&A_prof, seed_A_prof);
          random_poly_vec_eta(&s_prof);
          random_poly_vec_eta(&u_prof);
          random_poly_uniform(&v_prof);

          /* ---- Cycle profiling ---- */
          uint32_t t0, cyc_add, cyc_sub, cyc_ntt, cyc_inv, cyc_as;
          uint32_t cyc_s_transpose_u, cyc_v_sub_stu, cyc_v_sub_su;

          t0 = DWT->CYCCNT;
          ref_poly_add(&add_poly, &a_poly, &b_poly);
          cyc_add = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          ref_poly_sub(&sub_poly, &a_poly, &b_poly);
          cyc_sub = DWT->CYCCNT - t0;

          rt_poly = a_poly;
          t0 = DWT->CYCCNT;
          ntt(rt_poly.coeffs);
          cyc_ntt = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          invntt(rt_poly.coeffs);
          cyc_inv = DWT->CYCCNT - t0;

          /* Arith (A*s): 矩阵向量乘（核心 PKE 算术热点） */
          t0 = DWT->CYCCNT;
          ref_poly_matrix_vec_mul(&as_prof, &A_prof, &s_prof);
          cyc_as = DWT->CYCCNT - t0;

          /* Arith (v-su): 分别计时 s^T*u 与 v-(s^T*u)，并给出总计 */
          t0 = DWT->CYCCNT;
          ref_poly_vec_transpose_mul(&s_t_u_prof, &s_prof, &u_prof);
          cyc_s_transpose_u = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          ref_poly_sub(&diff_prof, &v_prof, &s_t_u_prof);
          cyc_v_sub_stu = DWT->CYCCNT - t0;
          cyc_v_sub_su = cyc_s_transpose_u + cyc_v_sub_stu;

          /* 将 roundtrip 结果从 Montgomery 域还原为标准域，便于展示 */
          for(int i = 0; i < MLWQ_N; i++)
            rt_poly.coeffs[i] = montgomery_reduce((int32_t)rt_poly.coeffs[i]);

          printf("cycles: add=%lu sub=%lu ntt=%lu invntt=%lu\r\n",
                 (unsigned long)cyc_add, (unsigned long)cyc_sub,
                 (unsigned long)cyc_ntt, (unsigned long)cyc_inv);
          printf("cycles arith: A*s=%lu v-su=%lu (sTu=%lu sub=%lu)\r\n",
                 (unsigned long)cyc_as, (unsigned long)cyc_v_sub_su,
                 (unsigned long)cyc_s_transpose_u, (unsigned long)cyc_v_sub_stu);

          printf("workspace bytes (poly): a=%u b=%u add=%u sub=%u ntt_rt=%u total=%u\r\n",
                 (unsigned)sizeof(a_poly),   (unsigned)sizeof(b_poly),
                 (unsigned)sizeof(add_poly), (unsigned)sizeof(sub_poly),
                 (unsigned)sizeof(rt_poly),
                 (unsigned)(sizeof(a_poly) + sizeof(b_poly) + sizeof(add_poly) +
                            sizeof(sub_poly) + sizeof(rt_poly)));
          printf("workspace bytes (arith): v=%u sTu=%u diff=%u s=%u u=%u As=%u A=%u seed=%u saved=%u total=%u\r\n",
                 (unsigned)sizeof(v_prof), (unsigned)sizeof(s_t_u_prof), (unsigned)sizeof(diff_prof),
                 (unsigned)sizeof(s_prof), (unsigned)sizeof(u_prof), (unsigned)sizeof(as_prof),
                 (unsigned)sizeof(A_prof), (unsigned)sizeof(seed_A_prof), (unsigned)sizeof(saved_coeffs),
                 (unsigned)(sizeof(v_prof) + sizeof(s_t_u_prof) + sizeof(diff_prof) +
                            sizeof(s_prof) + sizeof(u_prof) + sizeof(as_prof) +
                            sizeof(A_prof) + sizeof(seed_A_prof) + sizeof(saved_coeffs)));

          printf("sample a/add/rt first 4: %d %d %d %d / %d %d %d %d / %d %d %d %d\r\n",
                 a_poly.coeffs[0],   a_poly.coeffs[1],   a_poly.coeffs[2],   a_poly.coeffs[3],
                 add_poly.coeffs[0], add_poly.coeffs[1], add_poly.coeffs[2], add_poly.coeffs[3],
                 rt_poly.coeffs[0],  rt_poly.coeffs[1],  rt_poly.coeffs[2],  rt_poly.coeffs[3]);
          printf("\r\n");
        }
        else if(cmd == 'M' || cmd == 'm')
        {
          // ---------------------------------------------------------------
          // MLWQ Cycle Breakdown Profile (KeyGen / Encrypt / Decrypt)
          // 仅统计 Scalar 路径子组件，口径对齐为 Cortex-M4 单平台分解。
          // ---------------------------------------------------------------
          printf("MLWQ CYCLE BREAKDOWN PROFILE\r\n");

          /* 启用 DWT 周期计数器 */
          CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
          DWT->CYCCNT = 0;
          DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;

          /* 全部 static，避免大对象压栈 */
          static mlwq_pk pk_prof;
          static mlwq_sk sk_prof;
          static mlwq_ciphertext ct_prof;

          static poly_matrix A_prof, At_prof;
          static poly_vec As_prof, d_pk_prof, r_prof, Atr_prof, b_deq_prof, u_deq_prof;
          static poly d_v_prof, v_val_prof, m_poly_prof, v_final_prof, v_deq_prof, s_t_u_prof, diff_prof, zero_poly;

          static uint8_t seed_A[SEEDBYTES], seed_d[SEEDBYTES], seed_ct[SEEDBYTES], seed_s[SEEDBYTES];
          static uint8_t msg_in[32], msg_out[32], d_seed[33];
          const char *sep_line = "----------------------------------------------------------------------------------------------\r\n";

          uint32_t t0;
          uint32_t cyc_key_genA, cyc_key_sample_s, cyc_key_gendither, cyc_key_arith_as, cyc_key_quantize;
          uint32_t cyc_enc_arith_u, cyc_enc_arith_v;
          uint32_t cyc_dec_deq, cyc_dec_arith_vsu, cyc_dec_decode, cyc_dec_sTu, cyc_dec_sub;

          random_bytes(seed_A, SEEDBYTES);
          random_bytes(seed_d, SEEDBYTES);
          random_bytes(seed_ct, SEEDBYTES);
          random_bytes(msg_in, sizeof(msg_in));

          // -------------------------------
          // KeyGen Breakdown
          // -------------------------------
          t0 = DWT->CYCCNT;
          ref_xof_expand_matrix(&A_prof, seed_A);
          cyc_key_genA = DWT->CYCCNT - t0;

          random_bytes(seed_s, SEEDBYTES);
          t0 = DWT->CYCCNT;
          for(int i = 0; i < MLWQ_K; i++) {
            ref_poly_getnoise_eta1(&sk_prof.s.vec[i], seed_s, (uint8_t)i);
          }
          cyc_key_sample_s = DWT->CYCCNT - t0;

          for(int i = 0; i < SEEDBYTES; i++) d_seed[i] = seed_d[i];
          /* 与 keygen 实现一致：追加 0xFF 作为 dither 域分离字节 */
          d_seed[SEEDBYTES] = 0xFF;
          t0 = DWT->CYCCNT;
          ref_xof_expand_poly_vec(&d_pk_prof, d_seed, MLWQ_Q / P_PK);
          cyc_key_gendither = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          ref_poly_matrix_vec_mul(&As_prof, &A_prof, &sk_prof.s);
          cyc_key_arith_as = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          for(int i = 0; i < MLWQ_K; i++) {
            ref_poly_quantize(&pk_prof.b_q.vec[i], &As_prof.vec[i], &d_pk_prof.vec[i], P_PK);
          }
          cyc_key_quantize = DWT->CYCCNT - t0;

          for(int i = 0; i < SEEDBYTES; i++) {
            pk_prof.seed_A[i] = seed_A[i];
            pk_prof.seed_d[i] = seed_d[i];
          }
          for(int i = 0; i < MLWQ_N; i++) {
            zero_poly.coeffs[i] = 0;
          }

          // -------------------------------
          // Encrypt Breakdown (Arith only)
          // -------------------------------
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
          cyc_enc_arith_u = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          ref_poly_vec_transpose_mul(&v_val_prof, &b_deq_prof, &r_prof);
          cyc_enc_arith_v = DWT->CYCCNT - t0;

          // 构造可解密的 ct（不计入 breakdown）
          for(int i = 0; i < MLWQ_K; i++) {
            /* 这里使用 zero dither，仅用于构造稳定可解密样本，不参与分项计时 */
            ref_poly_quantize(&ct_prof.u.vec[i], &Atr_prof.vec[i], &zero_poly, P_U);
          }
          ref_poly_msg_encode(&m_poly_prof, msg_in);
          ref_poly_add(&v_final_prof, &v_val_prof, &m_poly_prof);
          ref_poly_quantize(&ct_prof.v, &v_final_prof, &d_v_prof, P_V);

          // -------------------------------
          // Decrypt Breakdown
          // -------------------------------
          t0 = DWT->CYCCNT;
          for(int i = 0; i < MLWQ_K; i++) {
            ref_poly_dequantize(&u_deq_prof.vec[i], &ct_prof.u.vec[i], P_U);
          }
          ref_poly_dequantize(&v_deq_prof, &ct_prof.v, P_V);
          cyc_dec_deq = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          ref_poly_vec_transpose_mul(&s_t_u_prof, &sk_prof.s, &u_deq_prof);
          cyc_dec_sTu = DWT->CYCCNT - t0;

          t0 = DWT->CYCCNT;
          ref_poly_sub(&diff_prof, &v_deq_prof, &s_t_u_prof);
          cyc_dec_sub = DWT->CYCCNT - t0;
          cyc_dec_arith_vsu = cyc_dec_sTu + cyc_dec_sub;

          t0 = DWT->CYCCNT;
          ref_poly_msg_decode(msg_out, &diff_prof);
          cyc_dec_decode = DWT->CYCCNT - t0;

          printf("%s", sep_line);
          printf(" PKE KeyGen Breakdown (Cortex-M4 Scalar)\r\n");
          printf("%s", sep_line);
          printf("GenMatrix (A): %lu\r\n", (unsigned long)cyc_key_genA);
          printf("Sample (s): %lu\r\n", (unsigned long)cyc_key_sample_s);
          printf("GenDither: %lu\r\n", (unsigned long)cyc_key_gendither);
          printf("Arith (A*s): %lu\r\n", (unsigned long)cyc_key_arith_as);
          printf("Quantize: %lu\r\n", (unsigned long)cyc_key_quantize);

          printf("%s", sep_line);
          printf(" PKE Encrypt Breakdown (Cortex-M4 Scalar)\r\n");
          printf("%s", sep_line);
          printf("Arith (u): %lu\r\n", (unsigned long)cyc_enc_arith_u);
          printf("Arith (v): %lu\r\n", (unsigned long)cyc_enc_arith_v);

          printf("%s", sep_line);
          printf(" PKE Decrypt Breakdown (Cortex-M4 Scalar)\r\n");
          printf("%s", sep_line);
          printf("DeQuantize: %lu\r\n", (unsigned long)cyc_dec_deq);
          printf("Arith (v-su): %lu (sTu=%lu sub=%lu)\r\n",
                 (unsigned long)cyc_dec_arith_vsu,
                 (unsigned long)cyc_dec_sTu,
                 (unsigned long)cyc_dec_sub);
          printf("Decode: %lu\r\n\r\n", (unsigned long)cyc_dec_decode);
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
