CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wmissing-prototypes -Wredundant-decls -O2 -fomit-frame-pointer -std=gnu99
NISTFLAGS ?= -Wno-unused-result -O2 -fomit-frame-pointer -std=gnu99
LDFLAGS ?= -lcrypto
LEVEL ?= 128
VIPERFLAGS = -DVIPER_LEVEL=$(LEVEL)

SOURCES = viper.c viper_arith.c fips202.c verify.c rng.c kem.c
HEADERS = viper_params.h api.h viper.h viper_arith.h fips202.h verify.h rng.h

all: test/viper_validation test/viper_bench

test/viper_validation: $(SOURCES) $(HEADERS) test/viper_validation.c
	$(CC) $(CFLAGS) $(VIPERFLAGS) -o $@ $(SOURCES) test/viper_validation.c $(LDFLAGS)

test/viper_bench: $(SOURCES) $(HEADERS) test/viper_bench.c test/cpucycles.c test/cpucycles.h
	$(CC) $(CFLAGS) $(VIPERFLAGS) -o $@ $(SOURCES) test/viper_bench.c test/cpucycles.c $(LDFLAGS)

.PHONY: clean test kat

test: test/viper_validation
	./test/viper_validation 1000

KAT_KEM: $(SOURCES) $(HEADERS) test/viper_kat_kem.c
	$(CC) $(CFLAGS) $(VIPERFLAGS) -o $@ $(SOURCES) test/viper_kat_kem.c $(LDFLAGS)

kat: KAT_KEM
	./KAT_KEM

clean:
	rm -f *.o test/viper_validation test/viper_bench test/test_kex test/kem test/PQCgenKAT_kem KAT_KEM PQCkemKAT_Viper*.req PQCkemKAT_Viper*.rsp *.req *.rsp
