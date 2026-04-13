// 1. 先包含我们自己写的led.h头文件
#include "led.h"

// 2. LED初始化函数（可选，因为CubeMX已经在main.c里初始化了GPIO，但封装一个更独立）
void LED_Init(void)
{
    // 这里的代码其实CubeMX已经在MX_GPIO_Init()里生成了，我们可以留空，或者重新配置一遍
    // 为了模块独立性，也可以在这里重新初始化一次PF9和PF10为推挽输出
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    // 使能GPIOF的时钟（非常重要，不使能时钟GPIO无法工作）
    __HAL_RCC_GPIOF_CLK_ENABLE();

    // 配置PF9和PF10为推挽输出
    GPIO_InitStruct.Pin = LED1_PIN | LED2_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(GPIOF, &GPIO_InitStruct);

    // 初始状态：两个LED都灭
    HAL_GPIO_WritePin(LED1_PORT, LED1_PIN, LED_OFF);
    HAL_GPIO_WritePin(LED2_PORT, LED2_PIN, LED_OFF);
}

// 3. LED1亮
void LED1_On(void)
{
    HAL_GPIO_WritePin(LED1_PORT, LED1_PIN, LED_ON);
}

// 4. LED1灭
void LED1_Off(void)
{
    HAL_GPIO_WritePin(LED1_PORT, LED1_PIN, LED_OFF);
}

// 5. LED1翻转
void LED1_Toggle(void)
{
    HAL_GPIO_TogglePin(LED1_PORT, LED1_PIN);
}

// 6. LED2亮
void LED2_On(void)
{
    HAL_GPIO_WritePin(LED2_PORT, LED2_PIN, LED_ON);
}

// 7. LED2灭
void LED2_Off(void)
{
    HAL_GPIO_WritePin(LED2_PORT, LED2_PIN, LED_OFF);
}

// 8. LED2翻转
void LED2_Toggle(void)
{
    HAL_GPIO_TogglePin(LED2_PORT, LED2_PIN);
}

// 9. 两个LED交替闪烁指定次数
void LED_Alternate_Flash(uint8_t times)
{
    // 第一阶段：D1单独闪烁times次，D2保持灭
    for(uint8_t i = 0; i < times; i++)
    {
        LED1_On();   // D1亮
        LED2_Off();  // D2灭
        HAL_Delay(300);
        LED1_Off();  // D1灭
        HAL_Delay(300);
    }

    // 第二阶段：D2单独闪烁times次，D1保持灭
    for(uint8_t i = 0; i < times; i++)
    {
        LED1_Off();  // D1灭
        LED2_On();   // D2亮
        HAL_Delay(300);
        LED2_Off();  // D2灭
        HAL_Delay(300);
    }

    // 闪烁完后，两个灯都灭
    LED1_Off();
    LED2_Off();
}
