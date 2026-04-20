#include "main.h"
#include "rng.h"
#include "rtc.h"
#include "usart.h"
#include "gpio.h"
#include "stdio.h"
#include "string.h"
#include "../saber_ref/api.h"
#include "../saber_ref/SABER_params.h"
#include "../saber_ref/SABER_indcpa.h"
#include "../saber_ref/poly.h"
#include "../saber_ref/pack_unpack.h"
#include "../saber_ref/fips202.h"
#include "../saber_ref/rng.h"

typedef struct { const char *name; uint64_t keygen_cycles, encaps_cycles, decaps_cycles; uint32_t keygen_success_count, encaps_success_count, decaps_success_count, error_count, mismatch_count; } kem_summary_t;
typedef struct { uint64_t total; uint32_t min, max, count; } cycle_stat_t;
typedef struct { cycle_stat_t keypair_total,keypair_rebuild_total,rng_seed_a,seed_a_hash,rng_seed_s,gen_matrix,sample,matvec,quantize,pack; } saber_keygen_breakdown_t;
typedef struct { cycle_stat_t indcpa_total,unpack,gen_matrix,sample,matvec,quantize_u,pack_u,unpack_pk,innerprod,decode_msg,quantize_v,pack_v,rebuild_total; } saber_encrypt_breakdown_t;
typedef struct { cycle_stat_t indcpa_total,unpack,innerprod,unpack_scale,recover,encode_msg,rebuild_total; } saber_decrypt_breakdown_t;

#define PROFILE_SEPARATOR "----------------------------------------------------------------------------------------------\r\n"
#define BENCH_ROUNDS 1000u
#define KEM_SCHEME_COL_WIDTH 12
#define KEM_CYCLES_COL_WIDTH 12
#define KEM_MISMATCH_COL_WIDTH 8
#define PROGRESS_UPDATE_INTERVAL_ROUNDS 100u
#define DERAND_ROUND_MULTIPLIER 17u
#define DERAND_INDEX_MULTIPLIER 31u
#define SABER_H1 (1u << (SABER_EQ - SABER_EP - 1))
#define SABER_H2 ((1u << (SABER_EP - 2)) - (1u << (SABER_EP - SABER_ET - 1)) + (1u << (SABER_EQ - SABER_EP - 1)))

uint8_t rx_buffer; uint8_t cmd_flag = 0; char cmd; extern RNG_HandleTypeDef hrng;

void SystemClock_Config(void);
static void run_kem_comparison_benchmark(void);
static void enable_cycle_counter(void);
static void run_saber_benchmark(uint32_t rounds,uint64_t *keygen_total,uint64_t *encaps_total,uint64_t *decaps_total,uint32_t *keygen_success_count,uint32_t *encaps_success_count,uint32_t *decaps_success_count,uint32_t *error_count,uint32_t *mismatch_count);
static void print_saber_data_sizes(void);
static void print_kem_summary_row(const kem_summary_t *summary);
static void run_saber_keygen_breakdown_benchmark(uint32_t rounds,saber_keygen_breakdown_t *breakdown,uint32_t *error_count);
static void run_saber_encrypt_breakdown_benchmark(uint32_t rounds,saber_encrypt_breakdown_t *breakdown,uint32_t *error_count);
static void run_saber_decrypt_breakdown_benchmark(uint32_t rounds,saber_decrypt_breakdown_t *breakdown,uint32_t *error_count);

int __io_putchar(int ch){ HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 100); return ch; }
int fputc(int ch, FILE *f){ (void)f; return __io_putchar(ch); }
int randombytes(unsigned char *x, unsigned long long xlen){
  unsigned long long generated=0ULL;
  while(generated<xlen){
    uint32_t value;
    unsigned long long chunk=xlen-generated;
    if(HAL_RNG_GenerateRandomNumber(&hrng,&value)!=HAL_OK) return RNG_BAD_OUTBUF;
    if(chunk>sizeof(value)) chunk=sizeof(value);
    for(unsigned long long i=0;i<chunk;i++) x[generated+i]=(uint8_t)(value>>(8u*i));
    generated+=chunk;
  }
  return RNG_SUCCESS;
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart){ if(huart->Instance==USART1){ cmd=rx_buffer; cmd_flag=1; HAL_UART_Receive_IT(&huart1,&rx_buffer,1);} }
static void enable_cycle_counter(void){ CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk; DWT->CYCCNT=0; DWT->CTRL|=DWT_CTRL_CYCCNTENA_Msk; }
static void print_report_separator(void){ printf("%s", PROFILE_SEPARATOR); }
static uint64_t safe_average(uint64_t total_cycles, uint32_t count){ return (count==0u)?0ULL:(total_cycles/count); }
static unsigned long cycle_u64_to_printable_ul(uint64_t cycles){ return (cycles>0xFFFFFFFFULL)?0xFFFFFFFFUL:(unsigned long)cycles; }
static void init_cycle_stat(cycle_stat_t *s){ s->total=0; s->min=0xFFFFFFFFu; s->max=0; s->count=0; }
static void add_cycle_sample(cycle_stat_t *s,uint32_t c){ s->total+=c; if(c<s->min)s->min=c; if(c>s->max)s->max=c; s->count++; }
static uint64_t average_cycle_stat(const cycle_stat_t *s){ return (s->count==0u)?0ULL:(s->total/s->count); }
static void fill_deterministic_bytes(uint8_t *buf, uint32_t len, uint32_t round){ for(uint32_t i=0;i<len;i++) buf[i]=(uint8_t)((round*DERAND_ROUND_MULTIPLIER)+(i*DERAND_INDEX_MULTIPLIER)+(round>>3)); }
static void print_breakdown_row(const char *name,const cycle_stat_t *stat,uint64_t total_avg){ uint64_t avg=average_cycle_stat(stat); uint64_t pct=(total_avg==0ULL)?0ULL:((avg*10000ULL)/total_avg); printf("%-24s | %-14lu | %3lu.%02lu\r\n",name,cycle_u64_to_printable_ul(avg),cycle_u64_to_printable_ul(pct/100ULL),cycle_u64_to_printable_ul(pct%100ULL)); }
static void print_round_progress(const char *stage,uint32_t done,uint32_t total,uint32_t *next){ if((done>=*next)||(done==total)){ printf("[PROGRESS][%s] round %lu/%lu\r\n",stage,(unsigned long)done,(unsigned long)total); if(done>=*next) *next += PROGRESS_UPDATE_INTERVAL_ROUNDS; } }

static void print_saber_data_sizes(void){
  printf(">>> PART 0: Protocol Data Sizes (Serialized/Wire Format)\r\n"); print_report_separator(); printf("%-35s %-15s\r\n","Component","Size (Bytes)"); print_report_separator();
  printf("[Saber] Public Key (pk):\r\n  %-33s %lu\r\n","CRYPTO_PUBLICKEYBYTES",(unsigned long)CRYPTO_PUBLICKEYBYTES);
  printf("[Saber] Secret Key (sk):\r\n  %-33s %lu\r\n","CRYPTO_SECRETKEYBYTES",(unsigned long)CRYPTO_SECRETKEYBYTES);
  printf("[Saber] Ciphertext (ct):\r\n  %-33s %lu\r\n","CRYPTO_CIPHERTEXTBYTES",(unsigned long)CRYPTO_CIPHERTEXTBYTES);
  printf("[Saber] Shared Secret (ss):\r\n  %-33s %lu\r\n","CRYPTO_BYTES",(unsigned long)CRYPTO_BYTES);
  print_report_separator(); printf("\r\n");
}

static void print_kem_summary_row(const kem_summary_t *summary){
  printf("%-*s | %*lu | %*lu | %*lu | %*lu\r\n",KEM_SCHEME_COL_WIDTH,summary->name,KEM_CYCLES_COL_WIDTH,cycle_u64_to_printable_ul(safe_average(summary->keygen_cycles,summary->keygen_success_count)),KEM_CYCLES_COL_WIDTH,cycle_u64_to_printable_ul(safe_average(summary->encaps_cycles,summary->encaps_success_count)),KEM_CYCLES_COL_WIDTH,cycle_u64_to_printable_ul(safe_average(summary->decaps_cycles,summary->decaps_success_count)),KEM_MISMATCH_COL_WIDTH,(unsigned long)summary->mismatch_count);
}

static void saber_keypair_from_seeds(uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES],uint8_t sk[SABER_INDCPA_SECRETKEYBYTES],const uint8_t seed_a_in[SABER_SEEDBYTES],const uint8_t seed_s[SABER_NOISE_SEEDBYTES]){
  uint16_t A[SABER_L][SABER_L][SABER_N]; uint16_t s[SABER_L][SABER_N]; uint16_t b[SABER_L][SABER_N]={0}; uint8_t seed_a[SABER_SEEDBYTES];
  memcpy(seed_a,seed_a_in,SABER_SEEDBYTES); shake128(seed_a,SABER_SEEDBYTES,seed_a,SABER_SEEDBYTES); GenMatrix(A,seed_a); GenSecret(s,seed_s); MatrixVectorMul(A,s,b,1);
  for(int i=0;i<SABER_L;i++) for(int j=0;j<SABER_N;j++) b[i][j]=(uint16_t)((b[i][j]+SABER_H1)>>(SABER_EQ-SABER_EP));
  POLVECq2BS(sk,s); POLVECp2BS(pk,b); memcpy(pk+SABER_POLYVECCOMPRESSEDBYTES,seed_a,SABER_SEEDBYTES);
}

static void run_saber_benchmark(uint32_t rounds,uint64_t *keygen_total,uint64_t *encaps_total,uint64_t *decaps_total,uint32_t *keygen_success_count,uint32_t *encaps_success_count,uint32_t *decaps_success_count,uint32_t *error_count,uint32_t *mismatch_count){
  static uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES],ct[CRYPTO_CIPHERTEXTBYTES],ss1[CRYPTO_BYTES],ss2[CRYPTO_BYTES];
  uint32_t t0,elapsed,next=PROGRESS_UPDATE_INTERVAL_ROUNDS; int ret;
  *keygen_total=*encaps_total=*decaps_total=0; *keygen_success_count=*encaps_success_count=*decaps_success_count=*error_count=*mismatch_count=0;
  for(uint32_t round=0; round<rounds; round++){
    t0=DWT->CYCCNT; ret=crypto_kem_keypair(pk,sk); elapsed=DWT->CYCCNT-t0; if(ret!=0){(*error_count)++; print_round_progress("KEM",round+1u,rounds,&next); continue;} *keygen_total+=elapsed; (*keygen_success_count)++;
    t0=DWT->CYCCNT; ret=crypto_kem_enc(ct,ss1,pk); elapsed=DWT->CYCCNT-t0; if(ret!=0){(*error_count)++; print_round_progress("KEM",round+1u,rounds,&next); continue;} *encaps_total+=elapsed; (*encaps_success_count)++;
    t0=DWT->CYCCNT; ret=crypto_kem_dec(ss2,ct,sk); elapsed=DWT->CYCCNT-t0; if(ret!=0){(*error_count)++; print_round_progress("KEM",round+1u,rounds,&next); continue;} *decaps_total+=elapsed; (*decaps_success_count)++;
    if(memcmp(ss1,ss2,CRYPTO_BYTES)!=0) (*mismatch_count)++; print_round_progress("KEM",round+1u,rounds,&next);
  }
}

static void run_saber_keygen_breakdown_benchmark(uint32_t rounds,saber_keygen_breakdown_t *bd,uint32_t *error_count){
  static uint8_t pk_ref[SABER_INDCPA_PUBLICKEYBYTES],sk_ref[SABER_INDCPA_SECRETKEYBYTES],pk_rb[SABER_INDCPA_PUBLICKEYBYTES],sk_rb[SABER_INDCPA_SECRETKEYBYTES],seed_a[SABER_SEEDBYTES],seed_s[SABER_NOISE_SEEDBYTES];
  static uint16_t A[SABER_L][SABER_L][SABER_N],s[SABER_L][SABER_N],b[SABER_L][SABER_N]={0}; uint32_t t0,tstart,next=PROGRESS_UPDATE_INTERVAL_ROUNDS;
  init_cycle_stat(&bd->keypair_total);init_cycle_stat(&bd->keypair_rebuild_total);init_cycle_stat(&bd->rng_seed_a);init_cycle_stat(&bd->seed_a_hash);init_cycle_stat(&bd->rng_seed_s);init_cycle_stat(&bd->gen_matrix);init_cycle_stat(&bd->sample);init_cycle_stat(&bd->matvec);init_cycle_stat(&bd->quantize);init_cycle_stat(&bd->pack); *error_count=0;
  for(uint32_t round=0; round<rounds; round++){
    t0=DWT->CYCCNT; indcpa_kem_keypair(pk_ref,sk_ref); add_cycle_sample(&bd->keypair_total,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; fill_deterministic_bytes(seed_a,SABER_SEEDBYTES,round); add_cycle_sample(&bd->rng_seed_a,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; shake128(seed_a,SABER_SEEDBYTES,seed_a,SABER_SEEDBYTES); add_cycle_sample(&bd->seed_a_hash,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; fill_deterministic_bytes(seed_s,SABER_NOISE_SEEDBYTES,round+1u); add_cycle_sample(&bd->rng_seed_s,DWT->CYCCNT-t0);
    tstart=DWT->CYCCNT;
    t0=DWT->CYCCNT; GenMatrix(A,seed_a); add_cycle_sample(&bd->gen_matrix,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; GenSecret(s,seed_s); add_cycle_sample(&bd->sample,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; MatrixVectorMul(A,s,b,1); add_cycle_sample(&bd->matvec,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; for(int i=0;i<SABER_L;i++) for(int j=0;j<SABER_N;j++) b[i][j]=(uint16_t)((b[i][j]+SABER_H1)>>(SABER_EQ-SABER_EP)); add_cycle_sample(&bd->quantize,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; POLVECq2BS(sk_rb,s); POLVECp2BS(pk_rb,b); memcpy(pk_rb+SABER_POLYVECCOMPRESSEDBYTES,seed_a,SABER_SEEDBYTES); add_cycle_sample(&bd->pack,DWT->CYCCNT-t0);
    add_cycle_sample(&bd->keypair_rebuild_total,DWT->CYCCNT-tstart);
    saber_keypair_from_seeds(pk_ref,sk_ref,seed_a,seed_s);
    if((memcmp(pk_ref,pk_rb,SABER_INDCPA_PUBLICKEYBYTES)!=0)||(memcmp(sk_ref,sk_rb,SABER_INDCPA_SECRETKEYBYTES)!=0)) (*error_count)++;
    print_round_progress("KEYGEN_BREAKDOWN",round+1u,rounds,&next);
  }
}

static void run_saber_encrypt_breakdown_benchmark(uint32_t rounds,saber_encrypt_breakdown_t *bd,uint32_t *error_count){
  static uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES],sk[SABER_INDCPA_SECRETKEYBYTES],ct_ref[SABER_BYTES_CCA_DEC],ct_rb[SABER_BYTES_CCA_DEC],m[SABER_KEYBYTES],seed_sp[SABER_NOISE_SEEDBYTES],seed_a[SABER_SEEDBYTES];
  static uint16_t A[SABER_L][SABER_L][SABER_N],sp[SABER_L][SABER_N],bp[SABER_L][SABER_N]={0},vp[SABER_N]={0},mp[SABER_N],b[SABER_L][SABER_N]; uint32_t t0,tstart,next=PROGRESS_UPDATE_INTERVAL_ROUNDS;
  init_cycle_stat(&bd->indcpa_total);init_cycle_stat(&bd->unpack);init_cycle_stat(&bd->gen_matrix);init_cycle_stat(&bd->sample);init_cycle_stat(&bd->matvec);init_cycle_stat(&bd->quantize_u);init_cycle_stat(&bd->pack_u);init_cycle_stat(&bd->unpack_pk);init_cycle_stat(&bd->innerprod);init_cycle_stat(&bd->decode_msg);init_cycle_stat(&bd->quantize_v);init_cycle_stat(&bd->pack_v);init_cycle_stat(&bd->rebuild_total);*error_count=0;
  for(uint32_t round=0; round<rounds; round++){
    fill_deterministic_bytes(seed_a,SABER_SEEDBYTES,round); fill_deterministic_bytes(seed_sp,SABER_NOISE_SEEDBYTES,round+1u); fill_deterministic_bytes(m,SABER_KEYBYTES,round+2u); saber_keypair_from_seeds(pk,sk,seed_a,seed_sp); fill_deterministic_bytes(seed_sp,SABER_NOISE_SEEDBYTES,round+3u);
    t0=DWT->CYCCNT; indcpa_kem_enc(m,seed_sp,pk,ct_ref); add_cycle_sample(&bd->indcpa_total,DWT->CYCCNT-t0);
    tstart=DWT->CYCCNT;
    t0=DWT->CYCCNT; memcpy(seed_a,pk+SABER_POLYVECCOMPRESSEDBYTES,SABER_SEEDBYTES); add_cycle_sample(&bd->unpack,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; GenMatrix(A,seed_a); add_cycle_sample(&bd->gen_matrix,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; GenSecret(sp,seed_sp); add_cycle_sample(&bd->sample,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; MatrixVectorMul(A,sp,bp,0); add_cycle_sample(&bd->matvec,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; for(int i=0;i<SABER_L;i++) for(int j=0;j<SABER_N;j++) bp[i][j]=(uint16_t)((bp[i][j]+SABER_H1)>>(SABER_EQ-SABER_EP)); add_cycle_sample(&bd->quantize_u,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; POLVECp2BS(ct_rb,bp); add_cycle_sample(&bd->pack_u,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; BS2POLVECp(pk,b); add_cycle_sample(&bd->unpack_pk,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; InnerProd(b,sp,vp); add_cycle_sample(&bd->innerprod,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; BS2POLmsg(m,mp); add_cycle_sample(&bd->decode_msg,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; for(int j=0;j<SABER_N;j++) vp[j]=(uint16_t)((vp[j]-(mp[j]<<(SABER_EP-1))+SABER_H1)>>(SABER_EP-SABER_ET)); add_cycle_sample(&bd->quantize_v,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; POLT2BS(ct_rb+SABER_POLYVECCOMPRESSEDBYTES,vp); add_cycle_sample(&bd->pack_v,DWT->CYCCNT-t0);
    add_cycle_sample(&bd->rebuild_total,DWT->CYCCNT-tstart);
    if(memcmp(ct_ref,ct_rb,SABER_BYTES_CCA_DEC)!=0) (*error_count)++;
    print_round_progress("ENC_BREAKDOWN",round+1u,rounds,&next);
  }
}

static void run_saber_decrypt_breakdown_benchmark(uint32_t rounds,saber_decrypt_breakdown_t *bd,uint32_t *error_count){
  static uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES],sk[SABER_INDCPA_SECRETKEYBYTES],ct[SABER_BYTES_CCA_DEC],m_ref[SABER_KEYBYTES],m_rb[SABER_KEYBYTES],seed_a[SABER_SEEDBYTES],seed_s[SABER_NOISE_SEEDBYTES],seed_sp[SABER_NOISE_SEEDBYTES];
  static uint16_t s[SABER_L][SABER_N],b[SABER_L][SABER_N],v[SABER_N]={0},cm[SABER_N]; uint32_t t0,tstart,next=PROGRESS_UPDATE_INTERVAL_ROUNDS;
  init_cycle_stat(&bd->indcpa_total);init_cycle_stat(&bd->unpack);init_cycle_stat(&bd->innerprod);init_cycle_stat(&bd->unpack_scale);init_cycle_stat(&bd->recover);init_cycle_stat(&bd->encode_msg);init_cycle_stat(&bd->rebuild_total);*error_count=0;
  for(uint32_t round=0; round<rounds; round++){
    fill_deterministic_bytes(seed_a,SABER_SEEDBYTES,round); fill_deterministic_bytes(seed_s,SABER_NOISE_SEEDBYTES,round+1u); fill_deterministic_bytes(seed_sp,SABER_NOISE_SEEDBYTES,round+2u); fill_deterministic_bytes(m_ref,SABER_KEYBYTES,round+3u);
    saber_keypair_from_seeds(pk,sk,seed_a,seed_s); indcpa_kem_enc(m_ref,seed_sp,pk,ct);
    t0=DWT->CYCCNT; indcpa_kem_dec(sk,ct,m_ref); add_cycle_sample(&bd->indcpa_total,DWT->CYCCNT-t0);
    tstart=DWT->CYCCNT;
    t0=DWT->CYCCNT; BS2POLVECq(sk,s); BS2POLVECp(ct,b); add_cycle_sample(&bd->unpack,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; InnerProd(b,s,v); add_cycle_sample(&bd->innerprod,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; BS2POLT(ct+SABER_POLYVECCOMPRESSEDBYTES,cm); add_cycle_sample(&bd->unpack_scale,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; for(int i=0;i<SABER_N;i++) v[i]=(uint16_t)((v[i]+SABER_H2-(cm[i]<<(SABER_EP-SABER_ET)))>>(SABER_EP-1)); add_cycle_sample(&bd->recover,DWT->CYCCNT-t0);
    t0=DWT->CYCCNT; POLmsg2BS(m_rb,v); add_cycle_sample(&bd->encode_msg,DWT->CYCCNT-t0);
    add_cycle_sample(&bd->rebuild_total,DWT->CYCCNT-tstart);
    if(memcmp(m_ref,m_rb,SABER_KEYBYTES)!=0) (*error_count)++;
    print_round_progress("DEC_BREAKDOWN",round+1u,rounds,&next);
  }
}

static void print_keygen_breakdown(const saber_keygen_breakdown_t *bd){ uint64_t total=average_cycle_stat(&bd->keypair_rebuild_total),base=average_cycle_stat(&bd->keypair_total); printf(">>> PART 1: Saber CPA-PKE KeyGen Breakdown (Cycles)\r\n"); print_report_separator(); printf("Baseline indcpa_kem_keypair avg=%lu, min=%lu, max=%lu\r\n",cycle_u64_to_printable_ul(base),(unsigned long)bd->keypair_total.min,(unsigned long)bd->keypair_total.max); printf("Rebuild total avg=%lu, min=%lu, max=%lu\r\n",cycle_u64_to_printable_ul(total),(unsigned long)bd->keypair_rebuild_total.min,(unsigned long)bd->keypair_rebuild_total.max); print_report_separator(); printf("%-24s | %-14s | %-12s\r\n","Stage","Avg Cycles","Share(%)"); print_report_separator(); print_breakdown_row("seed_A(gen)",&bd->rng_seed_a,total); print_breakdown_row("seed_A(hash)",&bd->seed_a_hash,total); print_breakdown_row("seed_s(gen)",&bd->rng_seed_s,total); print_breakdown_row("gen_matrix(A)",&bd->gen_matrix,total); print_breakdown_row("sample(s)",&bd->sample,total); print_breakdown_row("Arith (A*s)",&bd->matvec,total); print_breakdown_row("quantize(b)",&bd->quantize,total); print_breakdown_row("pack(pk,sk)",&bd->pack,total); print_breakdown_row("rebuild_total",&bd->keypair_rebuild_total,total); print_report_separator(); printf("\r\n"); }
static void print_encrypt_breakdown(const saber_encrypt_breakdown_t *bd){ uint64_t ind=average_cycle_stat(&bd->indcpa_total),reb=average_cycle_stat(&bd->rebuild_total); printf(">>> PART 2: Saber CPA-PKE Encrypt Breakdown (Cycles)\r\n"); print_report_separator(); printf("%-24s | %-14s | %-12s\r\n","Stage","Avg Cycles","Share(%)"); print_report_separator(); print_breakdown_row("unpack(seed_A)",&bd->unpack,reb); print_breakdown_row("gen_matrix(A)",&bd->gen_matrix,reb); print_breakdown_row("sample(sp)",&bd->sample,reb); print_breakdown_row("Arith (A*sp)",&bd->matvec,reb); print_breakdown_row("quantize(u)",&bd->quantize_u,reb); print_breakdown_row("pack(u)",&bd->pack_u,reb); print_breakdown_row("unpack(pk)",&bd->unpack_pk,reb); print_breakdown_row("Arith (b*sp)",&bd->innerprod,reb); print_breakdown_row("decode(msg)",&bd->decode_msg,reb); print_breakdown_row("quantize(v)",&bd->quantize_v,reb); print_breakdown_row("pack(v)",&bd->pack_v,reb); print_breakdown_row("rebuild_total",&bd->rebuild_total,reb); print_report_separator(); printf("indcpa_enc avg = %lu, rebuild_total avg = %lu\r\n\r\n",cycle_u64_to_printable_ul(ind),cycle_u64_to_printable_ul(reb)); }
static void print_decrypt_breakdown(const saber_decrypt_breakdown_t *bd){ uint64_t ind=average_cycle_stat(&bd->indcpa_total),reb=average_cycle_stat(&bd->rebuild_total); printf(">>> PART 3: Saber CPA-PKE Decrypt Breakdown (Cycles)\r\n"); print_report_separator(); printf("%-24s | %-14s | %-12s\r\n","Stage","Avg Cycles","Share(%)"); print_report_separator(); print_breakdown_row("unpack(ct,sk)",&bd->unpack,reb); print_breakdown_row("Arith (b*s)",&bd->innerprod,reb); print_breakdown_row("unpack(scale)",&bd->unpack_scale,reb); print_breakdown_row("recover(msgpoly)",&bd->recover,reb); print_breakdown_row("encode(msg)",&bd->encode_msg,reb); print_breakdown_row("rebuild_total",&bd->rebuild_total,reb); print_report_separator(); printf("indcpa_dec avg = %lu, rebuild_total avg = %lu\r\n\r\n",cycle_u64_to_printable_ul(ind),cycle_u64_to_printable_ul(reb)); }

static void run_kem_comparison_benchmark(void){
  kem_summary_t s={.name="Saber",.keygen_cycles=0,.encaps_cycles=0,.decaps_cycles=0,.keygen_success_count=0,.encaps_success_count=0,.decaps_success_count=0,.error_count=0,.mismatch_count=0};
  saber_keygen_breakdown_t kg; saber_encrypt_breakdown_t en; saber_decrypt_breakdown_t de; uint32_t kg_err=0,en_err=0,de_err=0;
  printf("\r\n=== Saber Comprehensive Benchmark Report ===\r\n"); printf("Rounds: %lu\r\n\r\n",(unsigned long)BENCH_ROUNDS); print_saber_data_sizes(); enable_cycle_counter();
  run_saber_benchmark(BENCH_ROUNDS,&s.keygen_cycles,&s.encaps_cycles,&s.decaps_cycles,&s.keygen_success_count,&s.encaps_success_count,&s.decaps_success_count,&s.error_count,&s.mismatch_count);
  run_saber_keygen_breakdown_benchmark(BENCH_ROUNDS,&kg,&kg_err); run_saber_encrypt_breakdown_benchmark(BENCH_ROUNDS,&en,&en_err); run_saber_decrypt_breakdown_benchmark(BENCH_ROUNDS,&de,&de_err);
  print_keygen_breakdown(&kg); print_encrypt_breakdown(&en); print_decrypt_breakdown(&de);
  printf(">>> PART 4: KEM Full Flow Summary (IND-CCA2)\r\n"); print_report_separator();
  printf("%-*s | %-*s | %-*s | %-*s | %-*s\r\n",KEM_SCHEME_COL_WIDTH,"Scheme",KEM_CYCLES_COL_WIDTH,"KeyGen",KEM_CYCLES_COL_WIDTH,"Encaps",KEM_CYCLES_COL_WIDTH,"Decaps",KEM_MISMATCH_COL_WIDTH,"Mismatch");
  print_report_separator(); print_kem_summary_row(&s); print_report_separator();
  printf("KEM operation error count: %lu\r\n",(unsigned long)s.error_count);
  printf("KeyGen breakdown error count: %lu\r\n",(unsigned long)kg_err);
  printf("Encrypt breakdown error count: %lu\r\n",(unsigned long)en_err);
  printf("Decrypt breakdown error count: %lu\r\n",(unsigned long)de_err);
  printf("KEM shared-secret mismatch count: %lu\r\n",(unsigned long)s.mismatch_count);
  printf("[FINAL] Benchmark complete.\r\n\r\n");
}

int main(void){
  HAL_Init(); SystemClock_Config(); MX_GPIO_Init(); MX_USART1_UART_Init(); MX_RNG_Init(); HAL_UART_Receive_IT(&huart1,&rx_buffer,1);
  printf("=========================\r\n  SABER TEST SYSTEM READY\r\n=========================\r\n");
  printf("TEST ROUNDS: %lu\r\n",(unsigned long)BENCH_ROUNDS);
  printf("CMD: C=RUN SABER COMPREHENSIVE REPORT (%lu rounds)\r\n",(unsigned long)BENCH_ROUNDS);
  printf("BUILD MODE: SABER-ONLY BENCHMARK\r\n=========================\r\n");
  while(1){ if(cmd_flag==1){ cmd_flag=0; if(cmd=='C'||cmd=='c') run_kem_comparison_benchmark(); else printf("ONLY CMD 'C' IS ENABLED\r\n\r\n"); } }
}

void SystemClock_Config(void){
  RCC_OscInitTypeDef RCC_OscInitStruct = {0}; RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  __HAL_RCC_PWR_CLK_ENABLE(); __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI|RCC_OSCILLATORTYPE_LSI; RCC_OscInitStruct.HSIState = RCC_HSI_ON; RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT; RCC_OscInitStruct.LSIState = RCC_LSI_ON; RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON; RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI; RCC_OscInitStruct.PLL.PLLM = 8; RCC_OscInitStruct.PLL.PLLN = 168; RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2; RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) Error_Handler();
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK|RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2; RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK; RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1; RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4; RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK) Error_Handler();
}

void Error_Handler(void){ __disable_irq(); while (1){} }
#ifdef USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line){ (void)file; (void)line; }
#endif
