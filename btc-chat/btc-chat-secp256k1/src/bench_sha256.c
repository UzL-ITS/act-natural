#include <string.h>

#include "include/secp256k1.h"
#include "hash_impl.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_sha256 hash;
    unsigned char data1[32];
    unsigned char data2[33];
} bench_sha256_data_t;

static void bench_sha256_setup(void *arg) {
    int i;
    bench_sha256_data_t *data = (bench_sha256_data_t *)arg;
    for (i = 0; i < 33; ++i) {
        data->data2[i] = 32 - i;
        if (i < 32) {
            data->data1[i] = i + 1;
        }
    }
}

static void bench_sha256(void *arg, int iters) {
    int i;
    unsigned char out[32];
    bench_sha256_data_t *data = (bench_sha256_data_t *)arg;
    for (i = 0; i < iters; ++i) {
        secp256k1_sha256_initialize(&data->hash);
        secp256k1_sha256_write(&data->hash, data->data1, 32);
        secp256k1_sha256_write(&data->hash, data->data2, 33);
        secp256k1_sha256_finalize(&data->hash, out);
    }
}

int main(void) {
    bench_sha256_data_t data;

    int iters = get_iters(20000);

    run_benchmark("sha256", bench_sha256, bench_sha256_setup, NULL, &data, 10, iters);

    return 0;
}