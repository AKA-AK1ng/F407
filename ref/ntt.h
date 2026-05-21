#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "..\common\params.h"

// 声明预计算的旋转因子表 (Twiddle Factors)
extern const int16_t zetas[128];

// 正向变换: 标准时域 -> NTT-Montgomery 域
// 输入：标准域系数 poly[i] ∈ Z_Q
// 输出：NTT-Montgomery 域（比特翻转顺序）
void ntt(int16_t poly[256]);

// 逆向变换: NTT-Montgomery 域 -> Montgomery 时域
// 输入：NTT-Montgomery 域系数（由 ntt() / basemul() 产生）
// 输出：Montgomery 时域，invntt(ntt(a))[i] = a[i] * R (mod Q)，R = 2^16
// 若需还原标准域系数，对每个结果系数调用 montgomery_reduce()
void invntt(int16_t poly[256]);

// 基乘法: 在 NTT 域中做点乘 (两个一次多项式的模乘)
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
