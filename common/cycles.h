#ifndef CYCLES_H
#define CYCLES_H

#include <stdint.h>

#if defined(_MSC_VER)
    #include <intrin.h>
    #define rdtsc_intrinsic __rdtsc
#elif defined(__GNUC__) || defined(__clang__)
    #include <x86intrin.h>
    #define rdtsc_intrinsic __rdtsc
#else
    #define rdtsc_intrinsic() 0
#endif

static inline unsigned long long start_cycles() {
    #if defined(__GNUC__) || defined(__clang__)
    _mm_lfence();
    #endif
    return rdtsc_intrinsic();
}

static inline unsigned long long stop_cycles() {
    #if defined(__GNUC__) || defined(__clang__)
    _mm_mfence();
    #endif
    return rdtsc_intrinsic();
}

#endif