#ifndef DWT_TIMER_H
#define DWT_TIMER_H

#include <stdint.h>

void dwt_timer_init(void);
uint32_t dwt_timer_now(void);
uint32_t dwt_timer_elapsed(uint32_t start, uint32_t end);

#endif
