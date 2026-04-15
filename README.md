# F407 M-LWQ Benchmark Project

本项目是一个基于 STM32F407 的 M-LWQ 实现与性能测试工程，核心目标是：

- 在 MCU 环境下运行 `ref` 版本的 PKE / KEM 流程；
- 使用 DWT 周期计数器（`DWT->CYCCNT`）做细粒度性能分解；
- 串口输出结构化 benchmark 报告。

---

## 目录结构说明

- `Src/main.c`  
  MCU 主程序入口、串口命令处理、benchmark 逻辑与结果打印。
- `common/`  
  公共参数与结构定义（如 `params.h`、`structs.h`、随机与哈希接口）。
- `ref/`  
  参考实现（PKE/KEM、多项式运算、XOF 等）。

---

## 当前测试逻辑

串口输入命令 `M` 后，主程序会执行：

1. 协议尺寸打印（PKE/KEM 关键对象字节数）；
2. 正确性预检查（KEM 一次封装/解封装一致性）；
3. 1000 轮 benchmark，统计以下部分平均周期：
   - PKE KeyGen 分解
   - PKE Encrypt 分解
   - PKE Decrypt 分解
   - PKE 全流程
   - KEM 全流程
4. mismatch 统计输出：
   - PKE decode mismatch count
   - KEM shared-secret mismatch count

---

## Benchmark 结果

```text
>> PART 1: Internal Breakdown (Scalar)
----------------------------------------------------------------------------------------------
 PKE KeyGen Breakdown (Avg, 1000 rounds)
----------------------------------------------------------------------------------------------
GenMatrix (A): 1227746
Sample (s): 419270
GenDither: 801805
Arith (A*s): 1991714
Quantize: 53475

----------------------------------------------------------------------------------------------
 PKE Encrypt Breakdown (Avg, 1000 rounds)
----------------------------------------------------------------------------------------------
GenMatrix (A): 1228214
Sample (r): 419271
GenDither (u): 801741
Arith (u): 1991702
Arith (v): 1167483
Quantize (u): 53475

----------------------------------------------------------------------------------------------
 PKE Decrypt Breakdown (Avg, 1000 rounds)
----------------------------------------------------------------------------------------------
DeQuantize: 33164
Arith (v-su): 1189417
Decode: 18364

>> PART 2: Core Component Comparison (Quantize vs Sample)
----------------------------------------------------------------------------------------------
KeyGen Quantize avg: 53475
KeyGen Sample avg: 419270
Sample/Quantize ratio: 7.84 x

>> PART 3: PKE Full Flow Summary (Total Time)
----------------------------------------------------------------------------------------------
PKE KeyGen: 4494012
PKE Encrypt: 5661888
PKE Decrypt: 1240946

>> PART 4: KEM Full Flow Summary (IND-CCA2)
----------------------------------------------------------------------------------------------
KEM KeyGen: 5191108
KEM Encaps: 6117629
KEM Decaps: 6665451

PKE decode mismatch count: 0
KEM shared-secret mismatch count: 0
[FINAL] Benchmark complete.
```

---

## 结果解读（简要）

- 正确性：`PKE/KEM mismatch = 0`，当前测试轮次下功能正确；
- KeyGen / Encrypt 中，`Arith` 与 `GenMatrix` 是主要耗时项；
- `Quantize` 占比相对较小，`Sample/Quantize = 7.84x`；
- KEM Decaps 是 KEM 三步中最耗时部分（当前结果下）。

---

## Kyber512 粗粒度 cycles 基准

`Src/main.c` 已新增串口命令 `C`，用于输出统一表格：

`Scheme | KeyGen | Encaps | Decaps | Mismatch`

### 说明

- `C` 命令当前仅测 Kyber512；
- 测量统一使用 `DWT->CYCCNT`，轮次与 MLWQ 主基准一致（`MLWQ_BENCH_ROUNDS`）。
