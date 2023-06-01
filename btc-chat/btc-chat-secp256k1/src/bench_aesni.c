#include <string.h>

#include "include/secp256k1.h"
#include "include/secp256k1_aesni.h"
#include "util.h"
#include "bench.h"

typedef struct {
    unsigned char key[32];
    unsigned char ptx[16];
    unsigned char iv[16];
    unsigned char ctx_ecb[16];
    unsigned char ctx_cbc[16];
} bench_aesni_data_t;

static void bench_aesni_setup(void *arg) {
    int i;
    unsigned char arr1[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
    };
    unsigned char arr2[16] = {
        0x0e, 0x23, 0x92, 0xdd, 0x6f, 0x69, 0x0b, 0x44, 0xa5, 0xa1, 0xb4, 0xfd, 0xff, 0x3b, 0x7f, 0x83
    };
    bench_aesni_data_t *data = (bench_aesni_data_t *)arg;
    for (i = 0; i < 32; ++i) {
        data->key[i] = i;
        if (i < 16) {
            data->ptx[i] = (i << 4) + i;
            data->ctx_ecb[i] = arr1[i];
            data->ctx_cbc[i] = arr2[i];
            data->iv[i] = i + 16;
        }
    }
}

static void bench_aesni_enc_key_expansion(void *arg, int iters) {
    int i;
    unsigned char key[15*16];
    bench_aesni_data_t *data = (bench_aesni_data_t *)arg;
    for (i = 0; i < iters; ++i) {
        secp256k1_aesni_256_key_expansion(key, data->key);
    }
}

static void bench_aesni_dec_key_expansion(void *arg, int iters) {
    int i;
    unsigned char tmp[15*16];
    unsigned char key[15*16];
    bench_aesni_data_t *data = (bench_aesni_data_t *)arg;
    for (i = 0; i < iters; ++i) {
        secp256k1_aesni_256_key_expansion(tmp, data->key);
        secp256k1_aesni_256_dec_key_expansion(key, tmp);
    }
}

static void bench_aesni_enc_ecb(void *arg, int iters) {
    int i;
    unsigned char res[16];
    unsigned char key[15*16];
    bench_aesni_data_t *data = (bench_aesni_data_t *)arg;
    for (i = 0; i < iters; ++i) {
        secp256k1_aesni_256_key_expansion(key, data->key);
        secp256k1_aesni_ecb_decrypt(res, data->ptx, 16, key, 14);
    }
}

static void bench_aesni_dec_ecb(void *arg, int iters) {
    int i;
    unsigned char res[16];
    unsigned char key[15*16];
    unsigned char tmp[15*16];
    bench_aesni_data_t *data = (bench_aesni_data_t *)arg;
    for (i = 0; i < iters; ++i) {
        secp256k1_aesni_256_key_expansion(tmp, data->key);
        secp256k1_aesni_256_dec_key_expansion(key, tmp);
        secp256k1_aesni_ecb_decrypt(res, data->ctx_ecb, 16, key, 14);
    }
}

static void bench_aesni_enc_cbc(void *arg, int iters) {
    int i;
    unsigned char res[16];
    unsigned char key[15*16];
    bench_aesni_data_t *data = (bench_aesni_data_t *)arg;
    for (i = 0; i < iters; ++i) {
        secp256k1_aesni_256_key_expansion(key, data->key);
        secp256k1_aesni_cbc_decrypt(res, data->ptx, data->iv, 16, key, 14);
    }
}

static void bench_aesni_dec_cbc(void *arg, int iters) {
    int i;
    unsigned char res[16];
    unsigned char key[15*16];
    unsigned char tmp[15*16];
    bench_aesni_data_t *data = (bench_aesni_data_t *)arg;
    for (i = 0; i < iters; ++i) {
        secp256k1_aesni_256_key_expansion(tmp, data->key);
        secp256k1_aesni_256_dec_key_expansion(key, tmp);
        secp256k1_aesni_cbc_decrypt(res, data->ctx_cbc, data->iv, 16, key, 14);
    }
}

int main(void) {
    bench_aesni_data_t data;

    int iters = get_iters(20000);

    run_benchmark("aesni-enc-keyexp", bench_aesni_enc_key_expansion, bench_aesni_setup, NULL, &data, 10, iters);
    run_benchmark("aesni-dec-keyexp", bench_aesni_dec_key_expansion, bench_aesni_setup, NULL, &data, 10, iters);

    run_benchmark("aesni-enc-ecb", bench_aesni_enc_ecb, bench_aesni_setup, NULL, &data, 10, iters);
    run_benchmark("aesni-dec-ecb", bench_aesni_enc_ecb, bench_aesni_setup, NULL, &data, 10, iters);

    run_benchmark("aesni-enc-cbc", bench_aesni_enc_cbc, bench_aesni_setup, NULL, &data, 10, iters);
    run_benchmark("aesni-dec-cbc", bench_aesni_enc_cbc, bench_aesni_setup, NULL, &data, 10, iters);

    return 0;
}