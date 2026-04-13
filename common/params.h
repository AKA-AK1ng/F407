#ifndef PARAMS_H
#define PARAMS_H

// === 配置 NIST 安全等级 (1, 3, 5) ===
#ifndef NIST_LEVEL
#define NIST_LEVEL 1
#endif

// -------------------------------------------------------------------------
// 1. 基础参数
// -------------------------------------------------------------------------
#define MLWQ_N 256
#define MLWQ_Q 3329
#define MLWQ_ETA1 3

#define SEEDBYTES 32
#define HASHBYTES 32

// -------------------------------------------------------------------------
// 2. 等级特定参数
// -------------------------------------------------------------------------
#if NIST_LEVEL == 1
    #define PARAM_NAME "M-LWQ-512 (L1)"
    #define MLWQ_K 2
    
    // L1: PK=10, U=9, V=5
    #define BIT_PK 10
    #define BIT_U  9
    #define BIT_V  5
    
    #define P_PK 1024
    #define P_U  512
    #define P_V  32

#elif NIST_LEVEL == 3
    #define PARAM_NAME "M-LWQ-768 (L3)"
    #define MLWQ_K 3
    
    // L3: PK=10, U=10, V=5
    #define BIT_PK 10
    #define BIT_U  10
    #define BIT_V  5
    
    #define P_PK 1024
    #define P_U  1024
    #define P_V  32

#elif NIST_LEVEL == 5
    #define PARAM_NAME "M-LWQ-1024 (L5)"
    #define MLWQ_K 4
    
    // L5: PK=10, U=10, V=5
    #define BIT_PK 10
    #define BIT_U  10
    #define BIT_V  5
    
    #define P_PK 1024
    #define P_U  1024
    #define P_V  32

#else
    #error "Invalid NIST_LEVEL"
#endif

// -------------------------------------------------------------------------
// 3. 自动计算字节大小 (关键修复区域)
// -------------------------------------------------------------------------

// --- 公钥/私钥打包 (PK) ---
#if BIT_PK == 9
    // 256 * 9 / 8 = 288
    #define MLWQ_POLYBYTES 288
#elif BIT_PK == 10
    // 256 * 10 / 8 = 320
    #define MLWQ_POLYBYTES 320
#else
    #error "Unsupported BIT_PK"
#endif

#define MLWQ_POLYVECBYTES (MLWQ_K * MLWQ_POLYBYTES)

// --- 密文 U 压缩 (自动适配) ---
// [关键修复] 不要硬编码 320，根据 BIT_U 自动选择
#if BIT_U == 9
    // 256 * 9 / 8 = 288
    #define MLWQ_POLY_U_BYTES 288
#elif BIT_U == 10
    // 256 * 10 / 8 = 320
    #define MLWQ_POLY_U_BYTES 320
#else
    #error "Unsupported BIT_U"
#endif

#define MLWQ_POLYVECCOMPRESSEDBYTES (MLWQ_K * MLWQ_POLY_U_BYTES)

// --- 密文 V 压缩 (5-bit) ---
#define MLWQ_POLYCOMPRESSEDBYTES 160

// --- 总大小 ---
#define MLWQ_CIPHERTEXTBYTES (MLWQ_POLYVECCOMPRESSEDBYTES + MLWQ_POLYCOMPRESSEDBYTES)
#define MLWQ_PUBLICKEYBYTES (MLWQ_POLYVECBYTES + SEEDBYTES)
#define MLWQ_SECRETKEYBYTES (MLWQ_POLYVECBYTES)
#define MLWQ_SSBYTES 32

#endif