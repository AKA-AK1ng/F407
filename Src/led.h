#ifndef __LED_H__
#define __LED_H__

#ifdef __cplusplus
extern "C" {
#endif

// 1. 包含STM32的HAL库头文件，因为我们要用HAL库的GPIO函数
#include "main.h"

// 2. 宏定义LED的引脚（方便以后换引脚，只需要改这里）
// 你的板子是PF9和PF10，低电平点亮
#define LED1_PIN    GPIO_PIN_9
#define LED1_PORT   GPIOF
#define LED2_PIN    GPIO_PIN_10
#define LED2_PORT   GPIOF

// 3. 宏定义LED的亮灭状态（低电平点亮，所以RESET是亮，SET是灭）
#define LED_ON      GPIO_PIN_RESET
#define LED_OFF     GPIO_PIN_SET

// 4. 函数声明（告诉别人有这些函数可以用）
void LED_Init(void);        // LED初始化函数（虽然CubeMX已经初始化了，但封装一个更规范）
void LED1_On(void);         // LED1亮
void LED1_Off(void);        // LED1灭
void LED1_Toggle(void);     // LED1翻转（亮变灭，灭变亮）
void LED2_On(void);         // LED2亮
void LED2_Off(void);        // LED2灭
void LED2_Toggle(void);     // LED2翻转
void LED_Alternate_Flash(uint8_t times); // 两个LED交替闪烁指定次数

#ifdef __cplusplus
}
#endif

#endif /* __LED_H__ */
