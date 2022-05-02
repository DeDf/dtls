#ifndef _A_TLS_H_INCLUDED_
#define _A_TLS_H_INCLUDED_

#define TLS_DEBUG  1

#include <stdio.h>
#include <winsock2.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/x509v3.h>

void __cdecl __report_rangecheckfailure(void);

#define u32 unsigned int
#define u16 unsigned short
#define s32 int
#define s16 short int
#define u8  unsigned char
#define s8  char

#define A_CRYPTO_MAX_EC_PUB_LEN     133//secp521
#define A_CRYPTO_MAX_MD_LEN         64
#define A_CRYPTO_MAX_KEY_LEN        64
#define A_CRYPTO_MAX_IV_LEN         16

typedef struct
{
    u8 *p;
    u8 *c;
    u32 p_len;
    u32 c_len;
    u32 type;

}crypto_info_t;

enum
{
    A_CRYPTO_GROUP_ID_SECP192R1 = 0x0013,
    A_CRYPTO_GROUP_ID_SECP256R1 = 0x0017,
    A_CRYPTO_GROUP_ID_SECP384R1 = 0x0018,
    A_CRYPTO_GROUP_ID_SECP521R1 = 0x0019,
    A_CRYPTO_GROUP_ID_X25519    = 0x001D,
};

#define likely(x)       (x) //__builtin_expect(!!(x), 1)
#define unlikely(x)     (x) //__builtin_expect(!!(x), 0)

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| (((unsigned int)(c[1]))    )),c+=2)

// 把u32截为u16并改变字节序
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                      c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

#define n2l(c,l)	(l =((unsigned long)(*((c)++)))<<24, \
                     l|=((unsigned long)(*((c)++)))<<16, \
                     l|=((unsigned long)(*((c)++)))<< 8, \
                     l|=((unsigned long)(*((c)++))))

#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                     *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                     *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                     *((c)++)=(unsigned char)(((l)    )&0xff))

#define n2l3(c,l)	((l =(((unsigned long)(c[0]))<<16)| \
                         (((unsigned long)(c[1]))<< 8)| \
                         (((unsigned long)(c[2]))    )),c+=3)

#define l2n3(l,c)	((c[0]=(unsigned char)(((l)>>16)&0xff), \
                      c[1]=(unsigned char)(((l)>> 8)&0xff), \
                      c[2]=(unsigned char)(((l)    )&0xff)),c+=3)

#define A_TLS_OK            0
#define A_TLS_ERR           -1

#define A_TLS_HEAD_LEN      5
#define A_TLS_RAND_SIZE     32
#define A_TLS_SESS_ID_SIZE  32

#define A_TLS_MASTER_KEY_LEN                48
#define A_TLS_PRE_MASTER_KEY_LEN            48
#define A_TLS_MASTER_SECRET_CONST		    "master secret"
#define A_TLS_MASTER_SECRET_CONST_LEN       13
#define A_TLS_KEY_EXPANSION_CONST		    "key expansion"
#define A_TLS_KEY_EXPANSION_CONST_LEN		13
#define A_TLS_MD_MAX_CONST_SIZE			    20
#define A_TLS_MD_CLIENT_FINISH_CONST        "client finished"
#define A_TLS_MD_CLIENT_FINISH_CONST_SIZE   15
#define A_TLS_MD_SERVER_FINISH_CONST        "server finished"
#define A_TLS_MD_SERVER_FINISH_CONST_SIZE   15
#define A_TLS_MASTER_KEY_BUF_LEN            (A_TLS_MASTER_SECRET_CONST_LEN + A_TLS_RAND_SIZE*2)
#define A_TLS_MAX_KB_LABEL_LEN              (A_TLS_KEY_EXPANSION_CONST_LEN + A_TLS_RAND_SIZE*2)

/*ccs flag*/
enum
{
    A_TLS_SECRET_READ       = (1<<0),
    A_TLS_SECRET_WRITE      = (1<<1),

    A_TLS_SECRET_CLNT       = (1<<2),
    A_TLS_SECRET_SRV        = (1<<3),
};

enum
{
    A_TLS_ECDSA_256             = 0x0403,
    A_TLS_ECDSA_384             = 0x0503,
    A_TLS_ECDSA_512             = 0x0603,

    A_TLS_RSAPSS_RSAE_SHA256    = 0x0804,
    A_TLS_RSAPSS_RSAE_SHA384    = 0x0805,
    A_TLS_RSAPSS_RSAE_SHA512    = 0x0806,

    /*ed*/
    A_TLS_ED25519               = 0x0807,
    A_TLS_ED448                 = 0x0808,

    A_TLS_RSAPSS_PSS_SHA256     = 0x0809,
    A_TLS_RSAPSS_PSS_SHA384     = 0x080a,
    A_TLS_RSAPSS_PSS_SHA512     = 0x080b,


    /*old*/
    A_TLS_EXT_RSA_SHA1          = 0x0201,
    A_TLS_EXT_RSA_SHA256        = 0x0401,
    A_TLS_EXT_RSA_SHA384        = 0x0501,
    A_TLS_EXT_RSA_SHA512        = 0x0601,

    A_TLS_EXT_ECDSA_SHA1        = 0x0203,
    //A_TLS_EXT_ECDSA_SHA224      = 0x0303,
    A_TLS_EXT_ECDSA_SHA256      = 0x0403,
    A_TLS_EXT_ECDSA_SHA384      = 0x0503,
    A_TLS_EXT_ECDSA_SHA512      = 0x0603,
};

enum
{
    A_TLS_GM                = (1<<0),
    A_TLS_1_0               = (1<<1),
    A_TLS_1_1               = (1<<2),
    A_TLS_1_2               = (1<<3),
    A_TLS_1_3               = (1<<4),
    A_TLS_VERSION_ALL_OLD   = A_TLS_1_0|A_TLS_1_1|A_TLS_1_2,
    A_TLS_VERSION_ALL       = A_TLS_VERSION_ALL_OLD|A_TLS_1_3,
};

enum
{
    A_TLS_GM_VERSION      = 0x0101,/*GM/T*/
    A_TLS_VERSION_MIN     = 0x0300,/*SSL 3.0 */
    A_TLS_TLS_1_0_VERSION = 0x0301,/*TLS 1.0*/
    A_TLS_TLS_1_1_VERSION = 0x0302,/*TLS 1.1*/
    A_TLS_TLS_1_2_VERSION = 0x0303,/*TLS 1.2*/
    A_TLS_TLS_1_3_DRAFT_VERSION = 0x7f1a,/*draft*/
    A_TLS_TLS_1_3_VERSION = A_TLS_TLS_1_3_DRAFT_VERSION,
    A_TLS_VERSION_MAX
};

enum {
    A_TLS_EXT_SRV_NAME   = 0x0000,
    A_TLS_EXT_STATUS_REQ = 0x0005,
    A_TLS_EXT_ALPN       = 0x0010,
    A_TLS_EXT_SUPPORT_GP = 0x000a,
    A_TLS_EXT_ECC_FORMAT = 0x000b,
    A_TLS_EXT_SIG_ALG    = 0x000d,
    A_TLS_EXT_SCTT       = 0x0012,
    A_TLS_EXT_ETM        = 0x0016,
    A_TLS_EXT_EMS        = 0x0017,
    A_TLS_EXT_SESS_TICKET= 0x0023,
    A_TLS_EXT_PSK        = 0x0029,
    A_TLS_EXT_EARLY_DATA = 0x002a,
    A_TLS_EXT_SUPPORT_VER= 0x002b,
    A_TLS_EXT_PSK_MODE   = 0x002d,
    A_TLS_EXT_ALG_CERT   = 0x0032,
    A_TLS_EXT_KEY_SHARE  = 0x0033,
    A_TLS_EXT_RENEGO     = 0xff01,
    A_TLS_EXT_MAX,
};

typedef struct {
    u8 type;
    u16 version;
    u16 len;
} d_tls_record_t;

typedef struct {
    u8 type;
    u8 len1;
    u8 len2;
    u8 len3;
} d_tls_hs_t;

#define D_TLS_KEY_BLOCK_MAX_LEN 0xA8
#define D_TLS_ECDH_PUB_MAX_LEN 0x130
#define D_TLS_ECDH_PRV_MAX_LEN 0x40

typedef struct {
    u8 key_block[D_TLS_KEY_BLOCK_MAX_LEN];
    u32 key_block_len;

    u8 self_ecdh_pub[D_TLS_ECDH_PUB_MAX_LEN];
    u8 self_ecdh_prv[D_TLS_ECDH_PRV_MAX_LEN];
    u32 self_ecdh_pub_len;
    u32 self_ecdh_prv_len;

    u8 clnt_random[A_TLS_RAND_SIZE];
    u8 srv_random[A_TLS_RAND_SIZE];

    u8 *digest_cache;
    u32 digest_offset;
    u32 digest_max_size;

} a_tls_handshake_t;


struct a_tls;
typedef struct a_tls a_tls_t;

typedef s32 (*state_func)(a_tls_t *);

#define CERT_SUM_MAX 5

typedef struct cert_ctx
{
    u8 *buf;
    u32 len;
} cert_ctx_t;

typedef struct {
    s8 *name;
    u32 tls_nid;

} sigalg_pair_t;

typedef struct
{
    s8 *name;
    u32 tls_nid;
    u32 openssl_nid;
    u32 md_nid;
    /*need init*/
    const EVP_CIPHER *c;
    const EVP_MD *md;

} d_cipher_t;

typedef struct
{
    s8 *name;
    u32 tls_nid;
    u32 openssl_nid;
    u32 field_len;
    const void *group;
} d_group_t;

#define  D_TLS_MSG_MAX_LEN  0x4000

struct a_tls
{
    u8 state;
    state_func          *state_proc;
    //
    a_tls_handshake_t   *handshake;
    u8 tmp_msg_buf[D_TLS_MSG_MAX_LEN];
    u8 master_secret[A_TLS_MASTER_KEY_LEN];
    //
    void                *write_ctx;
    void                *read_ctx;
    u16                 cipher_nid;
    d_cipher_t          *d_cipher;
    d_group_t           *d_group;

    s32 fd;
    s16 HostNameLen;
    s8  chHostName[1024];
    X509 *cert;
    EVP_PKEY *p_pub_key;
    EVP_PKEY *p_priv_key;  // server use
    cert_ctx_t cert_chain[CERT_SUM_MAX];

    u16 version;
    u16 handshake_version;

    u8 key[2][A_CRYPTO_MAX_KEY_LEN];
    u8 iv[2][A_CRYPTO_MAX_IV_LEN];
    u8 seq[2][8];
};

#endif
