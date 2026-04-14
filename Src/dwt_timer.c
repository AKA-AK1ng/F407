#include "dwt_timer.h"
#include "main.h"

void dwt_timer_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    DWT->CYCCNT = 0;
}

uint32_t dwt_timer_now(void)
{
    return DWT->CYCCNT;
}

uint32_t dwt_timer_elapsed(uint32_t start, uint32_t end)
{
    return end - start;
}
