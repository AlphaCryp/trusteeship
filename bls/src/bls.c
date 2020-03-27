#include <stdint.h>
#include <string.h>
#include <pbc.h>

 char *param = "type f\n\
 q 205523667896953300194896352429254920972540065223\n\
 r 205523667896953300194895899082072403858390252929\n\
 b 40218105156867728698573668525883168222119515413\n\
 beta 115334401956802802075595682801335644058796914268\n\
 alpha0 191079354656274778837764015557338301375963168470\n\
 alpha1 71445317903696340296199556072836940741717506375";

 void key_gen_c(uint8_t* out_sk, size_t *sk_len, uint8_t* out_pk, size_t *pk_len, uint8_t* out_g, size_t *g_len) {
    pairing_t pairing;
    element_t g;
    element_t public_key, secret_key;

    pairing_init_set_buf(pairing, param, strlen(param));
    element_init_G2(g, pairing);
    element_init_G2(public_key, pairing);
    element_init_Zr(secret_key, pairing);
    element_random(g);
    element_random(secret_key);
    element_pow_zn(public_key, g, secret_key);

    *sk_len = element_length_in_bytes(secret_key);
    element_to_bytes(out_sk, secret_key);

    *pk_len = element_length_in_bytes_compressed(public_key);
    element_to_bytes_compressed(out_pk, public_key);

    *g_len = element_length_in_bytes_compressed(g);
    element_to_bytes_compressed(out_g, g);

    element_clear(secret_key);
    element_clear(public_key);
    element_clear(g);
    pairing_clear(pairing);
 }

 void sign_c(uint8_t* out, size_t *out_len, uint8_t* msg, size_t msg_len, uint8_t* data) {
    pairing_t pairing;
    element_t secret_key;
    element_t sig;
    element_t h;

    pairing_init_set_buf(pairing, param, strlen(param));

    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    element_init_Zr(secret_key, pairing);

    element_from_bytes(secret_key, data);
    element_from_hash(h, msg, msg_len);
    element_pow_zn(sig, h, secret_key);

    *out_len = element_length_in_bytes_compressed(sig);
    element_to_bytes_compressed(out, sig);

    element_clear(sig);
    element_clear(secret_key);
    element_clear(h);
    pairing_clear(pairing);
 }

 int verify_c(uint8_t* msg, size_t msg_len, uint8_t* data_s, uint8_t* data_g, uint8_t* data_p) {
    pairing_t pairing;
    element_t public_key;
    element_t sig;
    element_t g, h;
    element_t temp1, temp2;

    pairing_init_set_buf(pairing, param, strlen(param));

    element_init_G2(g, pairing);
    element_init_G2(public_key, pairing);
    element_init_G1(sig, pairing);
    element_init_G1(h, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    element_from_bytes_compressed(public_key, data_p);
    element_from_bytes_compressed(g, data_g);
    element_from_bytes_compressed(sig, data_s);

    element_from_hash(h, msg, msg_len);

    pairing_apply(temp1, sig, g, pairing);
    pairing_apply(temp2, h, public_key, pairing);

    int r = !element_cmp(temp1, temp2);

    element_clear(sig);
    element_clear(public_key);
    element_clear(g);
    element_clear(h);
    element_clear(temp1);
    element_clear(temp2);
    pairing_clear(pairing);

    return r;
}


void aggregate_c(uint8_t* sig1, uint8_t* sig2, uint8_t* out, size_t *out_len) {
    element_t tmp;
    element_t sig_0;
    element_t sig_1;
    pairing_t pairing;

    pairing_init_set_buf(pairing, param, strlen(param));

    element_init_G1(sig_0, pairing);
    element_init_G1(sig_1, pairing);
    element_init_G1(tmp, pairing);


    element_from_bytes_compressed(sig_0, sig1);
    element_from_bytes_compressed(sig_1, sig2);
    element_mul(tmp, sig_0, sig_1);



    *out_len = element_length_in_bytes_compressed(tmp);
    element_to_bytes_compressed(out, tmp);

    element_clear(tmp);
    element_clear(sig_0);
    element_clear(sig_1);
}

void derived_c(uint8_t* g, uint8_t* rand, uint8_t* id, uint8_t* sk, uint8_t* out_sk, size_t *sk_len, uint8_t* out_pk, size_t *pk_len) {
    element_t rand_;
    element_t id_;
    element_t sk_;
    pairing_t pairing;
    element_t g_;
    element_t public_key, secret_key;

    pairing_init_set_buf(pairing, param, strlen(param));


    element_init_Zr(rand_, pairing);
    element_init_G2(g_, pairing);
    element_init_Zr(id_, pairing);
    element_init_Zr(sk_, pairing);
    element_init_Zr(secret_key, pairing);
    element_init_G2(public_key, pairing);

    element_from_bytes_compressed(g_, g);

    element_from_bytes(sk_, sk);
    element_from_bytes(rand_, rand);

    if (id[7] == 1) {
        element_set1(id_);
    } else {
        element_set_si(id_, 2);
    }

    element_mul(secret_key, rand_, id_);
    element_add(secret_key, secret_key, sk_);


    *sk_len = element_length_in_bytes(secret_key);
    element_to_bytes(out_sk, secret_key);

    element_pow_zn(public_key, g_, secret_key);

    *pk_len = element_length_in_bytes_compressed(public_key);
    element_to_bytes_compressed(out_pk, public_key);

    element_clear(rand_);
    element_clear(id_);
    element_clear(sk_);
    element_clear(public_key);
    element_clear(secret_key);
    element_clear(g_);
    pairing_clear(pairing);
}

void blind_c(uint8_t* msg, size_t msg_len, uint8_t* self_id,
uint8_t* other_id, uint8_t* msg_out, size_t* out_len,
uint8_t* tmp_out, size_t* tmp_len, uint8_t* sk,
uint8_t* tmp_out_1, size_t* tmp_len_1
) {
    element_t h;
    pairing_t pairing;
    element_t zero;
    element_t id_self, id_other;
    element_t tmp1, tmp2, tmp, tmp3;
    element_t sk_;


    pairing_init_set_buf(pairing, param, strlen(param));

    element_init_G1(h, pairing);
    element_init_Zr(zero, pairing);
    element_init_Zr(id_self, pairing);
    element_init_Zr(id_other, pairing);
    element_init_Zr(tmp1, pairing);
    element_init_Zr(tmp2, pairing);
    element_init_Zr(tmp, pairing);
    element_init_G1(tmp3, pairing);

    element_init_Zr(sk_, pairing);
    element_from_bytes(sk_, sk);

    element_from_hash(h, msg, msg_len);

    *tmp_len_1 = element_length_in_bytes(h);
    element_to_bytes(tmp_out_1, h);

    if (self_id[7] == 1) {
        element_set1(id_self);
        element_set_si(id_other, 2);
    } else {
        element_set1(id_other);
        element_set_si(id_self, 2);
    }



    element_set0(zero);


    element_sub(tmp1, zero, id_other);

    element_sub(tmp2, id_self, id_other);
    element_div(tmp, tmp1, tmp2);

    element_mul(sk_, tmp, sk_);

    *tmp_len = element_length_in_bytes(sk_);
    element_to_bytes(tmp_out, sk_);

    element_pow_zn(tmp3, h, tmp);

    *out_len = element_length_in_bytes(tmp3);
    element_to_bytes(msg_out, tmp3);

    element_clear(h);
    element_clear(zero);
    element_clear(id_self);
    element_clear(tmp);
    element_clear(id_other);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    pairing_clear(pairing);
}


void restore_c(uint8_t* s1, uint8_t* s2, uint8_t* s3, size_t* out_len) {
    element_t s1_,s2_;
    element_t s3_;
    pairing_t pairing;

    pairing_init_set_buf(pairing, param, strlen(param));

    element_init_Zr(s1_, pairing);
    element_init_Zr(s2_, pairing);
    element_init_Zr(s3_, pairing);
    element_from_bytes(s1_, s1);
    element_from_bytes(s2_, s2);

    element_add(s3_, s1_, s2_);

    *out_len = element_length_in_bytes(s3_);
    element_to_bytes(s3, s3_);

    element_clear(s1_);
    element_clear(s2_);
    element_clear(s3_);
    pairing_clear(pairing);
}


void rand_c(uint8_t* rand_out, size_t* out_len) {
    element_t rand;
    pairing_t pairing;

    pairing_init_set_buf(pairing, param, strlen(param));

    element_init_Zr(rand, pairing);
    element_random(rand);

    *out_len = element_length_in_bytes(rand);
    element_to_bytes(rand_out, rand);

    element_clear(rand);
    pairing_clear(pairing);
}


 void sign_group_c(uint8_t* out, size_t *out_len, uint8_t* msg, size_t msg_len, uint8_t* data) {
    pairing_t pairing;
    element_t secret_key;
    element_t sig;
    element_t h;

    pairing_init_set_buf(pairing, param, strlen(param));

    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    element_init_Zr(secret_key, pairing);

    element_from_bytes(secret_key, data);
    element_from_bytes(h, msg);
    element_pow_zn(sig, h, secret_key);

    *out_len = element_length_in_bytes_compressed(sig);
    element_to_bytes_compressed(out, sig);

    element_clear(sig);
    element_clear(secret_key);
    element_clear(h);
    pairing_clear(pairing);
 }
