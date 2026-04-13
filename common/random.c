#include "random.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <fcntl.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <sys/random.h>
#endif
#if defined(STM32F407xx)
#include "stm32f4xx_hal.h"
extern RNG_HandleTypeDef hrng;
#endif

void random_init() {
#if defined(STM32F407xx)
    // 注释掉！CubeMX 已经初始化了 RNG，这里不要重复写！
    // __HAL_RCC_RNG_CLK_ENABLE();
    // hrng.Instance = RNG;
    // if (HAL_RNG_Init(&hrng) != HAL_OK) {
    //     while (1) {}
    // }
#else
    // no-op: system RNG does not require initialization
#endif
}

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
static void read_urandom(uint8_t *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        abort();
    }
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = read(fd, out + offset, len - offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            abort();
        }
        if (n == 0) {
            close(fd);
            abort();
        }
        offset += (size_t)n;
    }
    close(fd);
}
#endif

void random_bytes(uint8_t *out, size_t len) {
#if defined(__APPLE__)
    arc4random_buf(out, len);
#elif defined(__linux__)
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = getrandom(out + offset, len - offset, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ENOSYS) {
                read_urandom(out + offset, len - offset);
                return;
            }
            abort();
        }
        offset += (size_t)n;
    }
#elif defined(STM32F407xx)
    size_t offset = 0;
    while (offset < len) {
        uint32_t val = 0;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &val) != HAL_OK) {
            if (HAL_RNG_DeInit(&hrng) != HAL_OK ||
                HAL_RNG_Init(&hrng) != HAL_OK ||
                HAL_RNG_GenerateRandomNumber(&hrng, &val) != HAL_OK) {
                /* Fail-safe: avoid deadlock and avoid fake entropy on hardware RNG failure. */
                for (; offset < len; offset++) {
                    out[offset] = 0;
                }
                return;
            }
        }
        size_t chunk = len - offset;
        if (chunk > 4) chunk = 4;
        for (size_t i = 0; i < chunk; i++) {
            out[offset++] = (uint8_t)(val >> (8 * i));
        }
    }
#else
#error "Unsupported platform for random_bytes"
#endif
}

void random_poly_uniform(poly *p) {
    for(int i=0; i<MLWQ_N; ++i) {
        uint16_t val = 0;
        random_bytes((uint8_t *)&val, sizeof(val));
        p->coeffs[i] = (int16_t)(val % MLWQ_Q);
    }
}


void random_poly_eta(poly *p) {
    for(int i=0; i<MLWQ_N; ++i) {
        // 模拟 CBD2: [-2, 2]
        // 概率: 0(37.5%), 1(25%), 2(6.25%)
        uint8_t byte = 0;
        random_bytes(&byte, sizeof(byte));
        int b0 = byte & 1;
        int b1 = (byte >> 1) & 1;
        int b2 = (byte >> 2) & 1;
        int b3 = (byte >> 3) & 1;
        p->coeffs[i] = (b0 + b1) - (b2 + b3);
    }
}

void random_poly_vec_eta(poly_vec *pv) {
    for(int i=0; i<MLWQ_K; ++i) {
        random_poly_eta(&pv->vec[i]);
    }
}
