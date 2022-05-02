
#include "a_tls.h"

#define D_TLS_MAX_CIPHER    4
#define D_TLS_MAX_SIG_ALG   8
#define D_TLS_MAX_GROUP     4

#define D_TLS_ECDH_PUB_LEN  65

enum {
    D_TLS_STATE_INIT,
    D_TLS_STATE_SND_CLNT_HELLO,
    D_TLS_STATE_GET_SRV_HELLO,
    D_TLS_STATE_GET_SRV_CERT,
    D_TLS_STATE_GET_SRV_KE,
    D_TLS_STATE_GET_SRV_HELLO_DONE,
    D_TLS_STATE_SND_CLNT_KE,
    D_TLS_STATE_SND_CLNT_CCS,
    D_TLS_STATE_SND_CLNT_FINISHED,
    D_TLS_STATE_GET_SRV_CCS,
    D_TLS_STATE_GET_SRV_FINISHED,
    D_TLS_STATE_ESTABLISH,
    D_TLS_STATE_MAX = D_TLS_STATE_ESTABLISH,
};

enum {
    D_TLS_HS_CLNT_HELLO          = 0x01,
    D_TLS_HS_SRV_HELLO           = 0x02,
    D_TLS_MT_SESS_TICKET         = 0x04,
//     A_TLS_MT_END_ED              = 0x05,
//     A_TLS_MT_ENC_EXTENSION       = 0x08,
    D_TLS_HS_CERT                = 0x0b,
    D_TLS_HS_SRV_KEYEXCHANGE     = 0x0c,
//     A_TLS_MT_SRV_CERT_REQ        = 0x0d,
    D_TLS_HS_SRV_HELLO_DONE      = 0x0e,
//     A_TLS_MT_CERTIFICATE_VERIFY  = 0x0f,
    D_TLS_HS_CLNT_KEYEXCHANGE    = 0x10,
    D_TLS_HS_FINISHED            = 0x14
};

// TLS Record Content type
enum
{
    D_TLS_RT_CCS = 0x14,
    D_TLS_RT_ALERT = 0x15,
    D_TLS_RT_HANDHSHAKE = 0x16,
    D_TLS_RT_APPLICATION_DATA = 0x17
};

enum
{
    D_TLS_ECDSA_256             = 0x0403,
    D_TLS_ECDSA_384             = 0x0503,
    D_TLS_ECDSA_512             = 0x0603,

    D_TLS_RSAPSS_RSAE_SHA256    = 0x0804,
    D_TLS_RSAPSS_RSAE_SHA384    = 0x0805,
    D_TLS_RSAPSS_RSAE_SHA512    = 0x0806,

    /*ed*/
    D_TLS_ED25519               = 0x0807,
    D_TLS_ED448                 = 0x0808,
};

// d_tls.c
a_tls_t *d_tls_new(int sock, char *pchHostName);
void d_tls_free(a_tls_t *tls);
s32 d_tls_handshake(a_tls_t *tls);


// d_tl_lib.c
void d_tls_free_hs(a_tls_handshake_t *hs);

u8 *d_tls_read(a_tls_t *tls, u32 *p_read_len);
s32 d_tls_write(a_tls_t *tls, u8 *buf, u32 len);

s32 d_tls_send_hs(a_tls_t *tls, u8 *data, s32 data_len);
s32 d_tls_save_hs(a_tls_t *tls, u8 *data, s32 data_len);
//
s32 d_tls_construct_clnt_hello(a_tls_t *tls, u8 *p);

int VerifyCerts(a_tls_t *tls);
s32 d_tls_select_cipher(a_tls_t *tls);

s32 a_tls_process_cke_ecdh(void *arg, u8 *in, u32 in_len);

u8 *d_tls_read_record_body(a_tls_t *tls, u8 type, s32 *p_body_len);
s32 d_tls_do_write(a_tls_t *tls, u8 *data, s32 data_len);

// d_tls_extension.c
s32 d_tls_ext_gen_server_name(a_tls_t *tls, u8 *ext);
s32 d_tls_ext_gen_support_gp(a_tls_t *tls, u8 *ext);
s32 a_tls_ext_gen_sig(a_tls_t *tls, u8 *ext);

// d_tls_crypto.h
s32 d_crypto_gen_ec_pub(d_group_t *group, u8 *prv, u8 *pub, u32 *prv_len, u32 *pub_len);
s32 d_crypto_verify_rsa_sign(a_tls_t *tls, EVP_MD *md, const u8 *pub_text_4, const u8 *sign_text);
s32 d_crypto_verify_ec_sign(a_tls_t *tls, EVP_MD *md, const u8 *pub_text_4, const u8 *sign_text);
//
s32 d_tls_init_cipher_aes_gcm(a_tls_t *tls, u32 flag);
s32 d_tls_enc_gcm(a_tls_t *tls, crypto_info_t *info);
s32 d_tls_dec_gcm(a_tls_t *tls, crypto_info_t *info);
//
s32 d_crypto_phash(const EVP_MD *md, u8 *sec, int sec_len, u8 *seed, u32 seed_len, u8 *out, u32 olen);
s32 d_tls_gen_master_secret(a_tls_t *tls, u8 *pms, u32 pms_len);

s32 a_crypto_calc_ec_shared(d_group_t *group, u8 *scale, u32 scale_len, u8 *f_point, u32 f_point_len, u8 *out, u32 *out_len);
