void secp256k1_aesni_256_key_expansion (
    unsigned char *key,
    const unsigned char *userkey
);

void secp256k1_aesni_256_dec_key_expansion (
    unsigned char *dec_key,
    const unsigned char *key_sched
);

void secp256k1_aesni_ecb_encrypt (
    unsigned char *out,
    const unsigned char *in,
    unsigned long length,
    const unsigned char *key,
    int number_of_rounds
);

void secp256k1_aesni_cbc_encrypt (
    unsigned char *out,
    const unsigned char *in,
    const unsigned char ivec[16],
    unsigned long length,
    const unsigned char *key,
    int number_of_rounds
);

void secp256k1_aesni_ecb_decrypt (
    unsigned char *out,
    const unsigned char *in,
    unsigned long length,
    const unsigned char *key,
    int number_of_rounds
);

void secp256k1_aesni_cbc_decrypt(
    unsigned char *out,
    const unsigned char *in,
    const unsigned char ivec[16],
    unsigned long length,
    const unsigned char *key,
    int number_of_rounds
);
