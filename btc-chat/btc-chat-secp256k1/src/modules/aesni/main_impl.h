#ifndef SECP256K1_MODULE_AESNI_MAIN_H
#define SECP256K1_MODULE_AESNI_MAIN_H

#include "include/secp256k1_aesni.h"

/**************************************************************/
/****************** AES-NI SECTION START **********************/
/**************************************************************/
/* see https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf */

#include <wmmintrin.h>

/*******************************/
/**        KEY SCHEDULE       **/
/*******************************/
__inline void secp256k1_aesni_key_256_assist_1 (__m128i *temp1, __m128i *temp2) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}
__inline void secp256k1_aesni_key_256_assist_2 (__m128i *temp1, __m128i *temp3) {
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}

void secp256k1_aesni_256_key_expansion (unsigned char *key, const unsigned char *userkey) {
    __m128i temp1, temp2, temp3;
    __m128i *Key_Schedule = (__m128i*)key;
    temp1 = _mm_loadu_si128((__m128i*)userkey);
    temp3 = _mm_loadu_si128((__m128i*)(userkey + 16));
    Key_Schedule[0] = temp1;
    Key_Schedule[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
    secp256k1_aesni_key_256_assist_1(&temp1, &temp2);
    Key_Schedule[2] = temp1;
    secp256k1_aesni_key_256_assist_2(&temp1, &temp3);
    Key_Schedule[3] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
    secp256k1_aesni_key_256_assist_1(&temp1, &temp2);
    Key_Schedule[4] = temp1;
    secp256k1_aesni_key_256_assist_2(&temp1, &temp3);
    Key_Schedule[5] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
    secp256k1_aesni_key_256_assist_1(&temp1, &temp2);
    Key_Schedule[6] = temp1;
    secp256k1_aesni_key_256_assist_2(&temp1, &temp3);
    Key_Schedule[7] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
    secp256k1_aesni_key_256_assist_1(&temp1, &temp2);
    Key_Schedule[8] = temp1;
    secp256k1_aesni_key_256_assist_2(&temp1, &temp3);
    Key_Schedule[9] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
    secp256k1_aesni_key_256_assist_1(&temp1, &temp2);
    Key_Schedule[10] = temp1;
    secp256k1_aesni_key_256_assist_2(&temp1, &temp3);
    Key_Schedule[11] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
    secp256k1_aesni_key_256_assist_1(&temp1, &temp2);
    Key_Schedule[12] = temp1;
    secp256k1_aesni_key_256_assist_2(&temp1, &temp3);
    Key_Schedule[13] = temp3;
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
    secp256k1_aesni_key_256_assist_1(&temp1, &temp2);
    Key_Schedule[14] = temp1;
}

void secp256k1_aesni_256_dec_key_expansion (unsigned char *dec_key, const unsigned char *key_sched) {
    #define ROUNDS 14
    int i;
    __m128i tmp;
    _mm_storeu_si128(&((__m128i*)dec_key)[0], ((__m128i*)key_sched)[ROUNDS]);
    for (i = 1; i < ROUNDS; ++i) {
        tmp = _mm_aesimc_si128(((__m128i*)key_sched)[ROUNDS-i]);
        _mm_storeu_si128(&((__m128i*)dec_key)[i], tmp);
    }
    _mm_storeu_si128(&((__m128i*)dec_key)[ROUNDS], ((__m128i*)key_sched)[0]);
    #undef ROUNDS
}

/*******************************/
/**        ENCRYPTION         **/
/*******************************/
/* Note – the length of the output buffer is assumed to be a multiple of 16 bytes */
void secp256k1_aesni_ecb_encrypt (
                    unsigned char *out,       /* pointer to the CIPHERTEXT buffer     */
                    const unsigned char *in,  /* pointer to the PLAINTEXT             */
                    unsigned long length,     /* text length in bytes                 */
                    const unsigned char *key, /* pointer to the expanded key schedule */
                    int number_of_rounds)     /* number of AES rounds 10, 12, or 14   */
{
    __m128i tmp;
    unsigned long i;
    int j;
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;
    for (i = 0; i < length; ++i) {
        tmp = _mm_loadu_si128(&((__m128i*)in)[i]);
        tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; ++j)
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);
        _mm_storeu_si128(&((__m128i*)out)[i], tmp);
    }
}

/* Note – the length of the output buffer is assumed to be a multiple of 16 bytes */
void secp256k1_aesni_cbc_encrypt (
                    unsigned char *out,             /* pointer to the CIPHERTEXT buffer     */
                    const unsigned char *in,        /* pointer to the PLAINTEXT             */
                    const unsigned char ivec[16],   /* pointer to the IV                    */
                    unsigned long length,           /* text length in bytes                 */
                    const unsigned char *key,       /* pointer to the expanded key schedule */
                    int number_of_rounds)           /* number of AES rounds 10, 12, or 14   */
{
    __m128i feedback,data;
    unsigned long i;
    int j;
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;
    feedback = _mm_loadu_si128((__m128i*)ivec);
    for (i = 0; i < length; ++i) {
        data = _mm_loadu_si128(&((__m128i*)in)[i]);
        feedback = _mm_xor_si128(data,feedback);
        feedback = _mm_xor_si128(feedback, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; ++j)
            feedback = _mm_aesenc_si128(feedback, ((__m128i*)key)[j]);
        feedback = _mm_aesenclast_si128(feedback, ((__m128i*)key)[j]);
        _mm_storeu_si128(&((__m128i*)out)[i], feedback);
    }
}

/*******************************/
/**        DECRYPTION         **/
/*******************************/
void secp256k1_aesni_ecb_decrypt(
                    unsigned char *out,       /* pointer to the DECRYPTED TEXT buffer */
                    const unsigned char *in,  /* pointer to the CIPHERTEXT            */
                    unsigned long length,     /* text length in bytes                 */
                    const unsigned char *key, /* pointer to the expanded key schedule */
                    int number_of_rounds)     /* number of AES rounds 10, 12, or 14   */
{
    __m128i tmp;
    unsigned long i;
    int j;
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;
    for (i = 0; i < length; i++) {
        tmp = _mm_loadu_si128(&((__m128i*)in)[i]);
        tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
            tmp = _mm_aesdec_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesdeclast_si128(tmp, ((__m128i*)key)[j]);
        _mm_storeu_si128(&((__m128i*)out)[i], tmp);
    }
}

void secp256k1_aesni_cbc_decrypt(
                    unsigned char *out,             /* pointer to the DECRYPTED TEXT buffer */
                    const unsigned char *in,        /* pointer to the CIPHERTEXT            */
                    const unsigned char ivec[16],   /* pointer to the IV                    */
                    unsigned long length,           /* text length in bytes                 */
                    const unsigned char *key,       /* pointer to the expanded key schedule */
                    int number_of_rounds)           /* number of AES rounds 10, 12, or 14   */
{
    __m128i data, feedback, last_in;
    unsigned long i;
    int j;
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;
    feedback = _mm_loadu_si128((__m128i*)ivec);
    for (i = 0; i < length; ++i) {
        last_in = _mm_loadu_si128(&((__m128i*)in)[i]);
        data = _mm_xor_si128(last_in, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; ++j) 
            data = _mm_aesdec_si128(data, ((__m128i*)key)[j]);
        data = _mm_aesdeclast_si128(data, ((__m128i*)key)[j]);
        data = _mm_xor_si128(data, feedback);
        _mm_storeu_si128(&((__m128i*)out)[i], data);
        feedback = last_in;
    }
}
/**************************************************************/
/****************** AES-NI SECTION END ************************/
/**************************************************************/

#endif /* SECP256K1_MODULE_AESNI_MAIN_H */
