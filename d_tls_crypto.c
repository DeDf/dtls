
#include "d_tls.h"

#if _DEBUG
#pragma comment ( lib, "libcrypto.lib" )
#else
#pragma comment ( lib, "libcrypto.lib" )
#endif

d_cipher_t d_ciphers[D_TLS_MAX_CIPHER] =
{
    /*TLS1.2's main ciphers*/
    /*ECDHE_ECDHE*/
    {
        "ECDHE_ECDHE_WITH_AES_128_GCM_SHA256",
        0xc02b,
        NID_aes_128_gcm,
        NID_sha256,
    },

    {
        "ECDHE_ECDHE_WITH_AES_256_GCM_SHA384",
        0xc02c,
        NID_aes_256_gcm,
        NID_sha384,
    },

    /*ECDHE_RSA*/
    {
        "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02f,
        NID_aes_128_gcm,
        NID_sha256,
    },

    {
        "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc030,
        NID_aes_256_gcm,
        NID_sha384,
    },
};

/*For client supporting sig_alg*/
sigalg_pair_t d_sigalg_pair[D_TLS_MAX_SIG_ALG] =
{
    {
        "rsa_pss_rsae_sha256",
        A_TLS_RSAPSS_RSAE_SHA256,
    },

    {
        "rsa_pss_rsae_sha384",
        A_TLS_RSAPSS_RSAE_SHA384,
    },

    {
        "rsa_pss_rsae_sha512",
        A_TLS_RSAPSS_RSAE_SHA512,
    },

    {
        "ecdsa_secp256r1_sha256",
        A_TLS_ECDSA_256,
    },

    {
        "ecdsa_secp384r1_sha384",
        A_TLS_ECDSA_384,
    },

    {
        "ecdsa_secp521r1_sha512",
        A_TLS_ECDSA_512,
    },
#ifdef NID_X25519
    {
        "ed25519",
        A_TLS_ED25519,
    },
#endif
#ifdef NID_X448
    {
        "ed448",
        A_TLS_ED448,
    },
#endif
};

d_group_t d_groups[D_TLS_MAX_GROUP] =
{
    {
        "secp256r1",
        A_CRYPTO_GROUP_ID_SECP256R1,
        NID_X9_62_prime256v1,
        0,
        NULL,
    },

    {
        "secp384r1",
        A_CRYPTO_GROUP_ID_SECP384R1,
        NID_secp384r1,
        0,
        NULL,
    },

    {
        "secp521r1",
        A_CRYPTO_GROUP_ID_SECP521R1,
        NID_secp521r1,
        0,
        NULL,
    },

#ifdef NID_X25519
    {
        "X25519",
        A_CRYPTO_GROUP_ID_X25519,
        NID_X25519,
        0,
        NULL,
    },
#endif
};

void d_mgf1(EVP_MD *md, u8 *dst, u32 dst_len, u8 *src, u32 src_len)
{
    unsigned char tmp[A_CRYPTO_MAX_MD_LEN] = {0}, tmp2[A_CRYPTO_MAX_MD_LEN];
    unsigned char *p = dst, *ctr;
    unsigned int mask_len, hash_len = src_len, i;
    unsigned int tmp2_len;

    memcpy(tmp, src, src_len);
    ctr = tmp + src_len;

    while ((int)dst_len > 0)
    {
        EVP_Digest(tmp, src_len + 4, tmp2, &tmp2_len, md, NULL);

        mask_len = dst_len < hash_len ? dst_len : hash_len;

        for (i = 0; i < mask_len; i++)
        {
            *p++ ^= tmp2[i];
        }

        dst_len -= mask_len;
        ctr[3]++;
    }
}

s32 d_light_rsa_add_pss_padding(EVP_MD *md, u8 *in, u32 in_len, u8 *out, u32 out_len)
{
    u8 *salt;
    u8 tmp[8 + A_CRYPTO_MAX_MD_LEN*2]={0};
    u8 *p = out;
    u32 hash_len = in_len;

    memset(p, 0, out_len - 2 - hash_len * 2);

    /*radnom salt*/
    salt = (p + out_len - 2 - hash_len * 2);

    *salt++ = 0x01;

    /*Random*/
    memset(salt, 0x12, hash_len);

    memcpy(tmp + 8, in, hash_len);
    memcpy(tmp + 8 + hash_len, salt, hash_len);

    EVP_Digest(tmp, 8 + hash_len + hash_len, p + out_len - hash_len - 1, &hash_len, md, NULL);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("rsa pss md in\n");
        for(k=0;k<8+hash_len+hash_len;k++)
        {
            printf("%02X", tmp[k]);
        }
        printf("\n");

        printf("rsa pss m' \n");
        for(k=0;k<hash_len;k++)
        {
            printf("%02X", (p + out_len - hash_len - 1)[k]);
        }
        printf("\n");
    }
#endif
    d_mgf1(md, out, out_len - hash_len - 1, p + out_len - hash_len - 1, hash_len);
    out[out_len - 1] = 0xBC;
    out[0] &= 0xFF >> 1;

    return A_TLS_OK;
    /*Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.*/
}

// 服务器用的，RSA签名函数
s32 d_crypto_rsa_sign(a_tls_t *tls, EVP_MD *md, u8 *pub_text)
{
    EVP_PKEY *rsa_key = tls->p_priv_key;
    RSA *rsa;
    u32 rsa_out_len;
    u8  buf_512_1[512];
    u8  buf_512_2[512];
    u32 hash_len = 0x20;
    u8  *tbs = buf_512_2;
    u8 *p = tbs;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    rsa = EVP_PKEY_get0_RSA(rsa_key);
#else
    rsa = rsa_key->pkey.rsa;
#endif

    rsa_out_len = RSA_size(rsa);
    memcpy(p, tls->handshake->clnt_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;
    //
    memcpy(p, tls->handshake->srv_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;
    //
    memcpy(p, pub_text, D_TLS_ECDH_PUB_LEN + 4);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("tbs (clnt_random[32] srv_random[32] pub[1+2+1+%d]) : %d\n", D_TLS_ECDH_PUB_LEN, 133);
        printf("clnt_random:\n"); {for(k=0; k<32;k++)       printf("%02X", tbs[k]);} printf("\n");
        printf("srv_random:\n");  {for(k=32;k<64;k++)       printf("%02X", tbs[k]);} printf("\n");
        printf("pub start:\n");   {for(k=64;k<133;k++)      printf("%02X", tbs[k]);} printf("\n");
    }
#endif

    if(!EVP_Digest(tbs, 133, buf_512_1, &hash_len, md, NULL)) {
        goto L_error;
    }

    //do padding;
    d_light_rsa_add_pss_padding(md, buf_512_1, hash_len, buf_512_2, rsa_out_len);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("rsa in :%d\n",rsa_out_len);
        for(k=0;k<rsa_out_len;k++)
        {
            printf("%02X", buf_512_2[k]);
        }
        printf("\n");
    }
#endif

    if (RSA_private_encrypt(rsa_out_len, buf_512_2, buf_512_1, rsa, RSA_NO_PADDING) <= 0)
    {
        goto L_error;
    }

    return A_TLS_OK;

L_error:
    return A_TLS_ERR;
}

s32 d_crypto_verify_rsa_sign(a_tls_t *tls, EVP_MD *md, const u8 *pub_text_4, const u8 *sign_text)
{
    EVP_PKEY *rsa_key = tls->p_pub_key;
    RSA *rsa;
    u32 rsa_out_len;
    u8  plain_text[512+4];
    u32 hash_len = 0x20;
    u8  tmp[8 + A_CRYPTO_MAX_MD_LEN*2];
    u8 *hash = tmp + 8;
    u8 *salt = tmp + 8 + hash_len;
    u8 *p;
    u16 sign_len;
    u8 *pRnd2PubHash;
    u8 *cnt;
    ULONG i;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    rsa = EVP_PKEY_get0_RSA(rsa_key);
#else
    rsa = rsa_key->pkey.rsa;
#endif

    rsa_out_len = RSA_size(rsa);

    p = sign_text;
    n2s(p, sign_len);
    if (sign_len != rsa_out_len)  // rsa 2048 bit
        goto L_error;

    if (RSA_public_decrypt(rsa_out_len, p, plain_text, rsa, RSA_NO_PADDING) <= 0)
    {
        goto L_error;
    }

    p = plain_text + rsa_out_len - 1;
    if (*p != 0xbc)
        goto L_error;

    pRnd2PubHash = plain_text + rsa_out_len - 1 - hash_len;
    cnt = pRnd2PubHash + hash_len;
    cnt[0] = 0;
    cnt[1] = 0;
    cnt[2] = 0;
    cnt[3] = 6;
    EVP_Digest(pRnd2PubHash, hash_len + 4, hash, &hash_len, md, NULL);

    p = plain_text + rsa_out_len - hash_len * 2;
    //
    for (i = 0; i < hash_len-1; i++)
    {
        salt[i+1] = hash[i] ^ p[i];
    }

    cnt[3] = 5;
    EVP_Digest(pRnd2PubHash, hash_len + 4, hash, &hash_len, md, NULL);
    p = plain_text + rsa_out_len - hash_len * 2 - 1;
    salt[0] = *p ^ hash[hash_len-1];

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("rsa sign salt:\n"); {for(k=0; k<hash_len;k++)  printf("%02X", salt[k]);} printf("\n");
    }
#endif

    //---------------------------------------------------------

    p = plain_text;
    memcpy(p, tls->handshake->clnt_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;
    //
    memcpy(p, tls->handshake->srv_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;
    //
    memcpy(p, pub_text_4, D_TLS_ECDH_PUB_LEN + 4);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("tbs (clnt_random[32] srv_random[32] pub[1+2+1+%d]) : %d\n", D_TLS_ECDH_PUB_LEN, 133);
        printf("clnt_random:\n"); {for(k=0; k<32;k++)       printf("%02X", plain_text[k]);} printf("\n");
        printf("srv_random:\n");  {for(k=32;k<64;k++)       printf("%02X", plain_text[k]);} printf("\n");
        printf("pub start:\n");   {for(k=64;k<133;k++)      printf("%02X", plain_text[k]);} printf("\n");
    }
#endif

    EVP_Digest(plain_text, 133, hash, &hash_len, md, NULL);

    memset(tmp, 0, 8);
//     memcpy(tmp + 8, hash, hash_len);
//     memcpy(tmp + 8 + hash_len, salt, hash_len);
    EVP_Digest(tmp, 8 + hash_len + hash_len, hash, &hash_len, md, NULL);

    if (memcmp(hash, pRnd2PubHash, hash_len))
        goto L_error;

    return A_TLS_OK;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}


s32 d_crypto_verify_ec_sign(a_tls_t *tls, EVP_MD *md, const u8 *pub_text_4, const u8 *sign_text)
{
    EC_KEY *ec;
    EVP_PKEY *ec_key = tls->p_pub_key;
    u8  plain_text[133];
    u32 hash_len = 0x20;
    u8  hash[A_CRYPTO_MAX_MD_LEN];
    u16 pub_len;
    u16 sign_len;
    int verify;
    u8 *p;

    p = sign_text;
    n2s(p, sign_len);
    if (sign_len > 0x100)
        goto L_error;

    pub_len = pub_text_4[3];
    if (pub_len > 65)
        goto L_error;

    p = plain_text;
    memcpy(p, tls->handshake->clnt_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;
    //
    memcpy(p, tls->handshake->srv_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;
    //
    memcpy(p, pub_text_4, pub_len + 4);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("tbs (clnt_random[32] srv_random[32] pub[1+2+1+%d]) : %d\n", pub_len, 64+4+pub_len);
        printf("clnt_random:\n"); {for(k=0; k<32;k++)       printf("%02X", plain_text[k]);} printf("\n");
        printf("srv_random:\n");  {for(k=32;k<64;k++)       printf("%02X", plain_text[k]);} printf("\n");
        printf("pub start:\n");   {for(k=64;k<64+4+(u32)pub_len;k++)      printf("%02X", plain_text[k]);} printf("\n");
    }
#endif

    EVP_Digest(plain_text, 64+4+pub_len, hash, &hash_len, md, NULL);

#ifdef TLS_DEBUG
    {
        u32 k;
        printf("mhash:%d\n",hash_len);
        for(k=0;k<hash_len;k++)
        {
            printf("%02X", hash[k]);
        }
        printf("\n");
    }
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ec = EVP_PKEY_get0_EC_KEY(ec_key);
#else
    ec = ec_key->pkey.ec;
#endif
    
    verify = ECDSA_verify(EVP_PKEY_EC, hash, hash_len, sign_text+2, sign_len, ec);
    if (verify == 1)
        return A_TLS_OK;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 d_tls_calc_key_block(a_tls_t *tls)
{
    d_cipher_t *cipher;
    u32 iv_len, key_len, hash_len, kb_size;
    u8 *p, buf[A_TLS_MAX_KB_LABEL_LEN];

    cipher = tls->d_cipher;

    iv_len   = 4;
    key_len  = EVP_CIPHER_key_length(cipher->c);
    hash_len = EVP_MD_size(cipher->md);

    /*generate key block*/
    if(tls->handshake->key_block[0] == 0)
    {
        kb_size = (iv_len + key_len + hash_len)<<1;
        if (tls->handshake->key_block == NULL)
        {
            return A_TLS_ERR;
        }

        p = buf;
        memcpy(p, A_TLS_KEY_EXPANSION_CONST, A_TLS_KEY_EXPANSION_CONST_LEN);
        p +=  A_TLS_KEY_EXPANSION_CONST_LEN;

        memcpy(p, tls->handshake->srv_random, A_TLS_RAND_SIZE);
        p += A_TLS_RAND_SIZE;

        memcpy(p, tls->handshake->clnt_random, A_TLS_RAND_SIZE);

        d_crypto_phash(tls->d_cipher->md,
            tls->master_secret, A_TLS_PRE_MASTER_KEY_LEN,
            buf, sizeof(buf),
            tls->handshake->key_block, kb_size);

#ifdef TLS_DEBUG
        {
            u32 i;
            printf("kb_size:%d\n", kb_size);
            for(i=0;i<kb_size;i++)
            {
                printf("%02X", tls->handshake->key_block[i]);
            }
            printf("\n");
        }
#endif
    }

    return A_TLS_OK;
}

s32 d_tls_init_cipher_aes_gcm(a_tls_t *tls, u32 flag)
{
    s32 ret;
    void *cipher_key, *cipher_iv;
    EVP_CIPHER_CTX *ctx;
    d_cipher_t *cipher;
    u32 iv_len, key_len;
    u8 *p;

    ret = d_tls_calc_key_block(tls);
    if (ret)
        return ret;

    cipher = tls->d_cipher;
    key_len = EVP_CIPHER_key_length(cipher->c);
    iv_len = 4;

    if (flag&A_TLS_SECRET_WRITE)
    {
        if (tls->write_ctx)
        {
            EVP_CIPHER_CTX_cleanup(tls->write_ctx);
        }
        else
        {
            tls->write_ctx = EVP_CIPHER_CTX_new();
        }
        ctx = tls->write_ctx;
        cipher_key = tls->key[1];
        cipher_iv = tls->iv[1];
    }
    else
    {
        if (tls->read_ctx)
        {
            EVP_CIPHER_CTX_cleanup(tls->read_ctx);
        }
        else
        {
            tls->read_ctx = EVP_CIPHER_CTX_new();
        }
        ctx = tls->read_ctx;
        cipher_key = tls->key[0];
        cipher_iv = tls->iv[0];
    }

    p = tls->handshake->key_block;
    /*server write*/

    if ((flag&A_TLS_SECRET_SRV  && flag&A_TLS_SECRET_WRITE) ||
        (flag&A_TLS_SECRET_CLNT && flag&A_TLS_SECRET_READ))

    {
        p += key_len;
        memcpy(cipher_key, p, key_len);
        p += key_len;
        p += iv_len;
        memcpy(cipher_iv, p, iv_len);
    }
    else if ((flag&A_TLS_SECRET_SRV  && flag&A_TLS_SECRET_READ) ||
             (flag&A_TLS_SECRET_CLNT && flag&A_TLS_SECRET_WRITE))
    {
        memcpy(cipher_key, p, key_len);
        p += key_len;
        p += key_len;
        memcpy(cipher_iv, p, iv_len);
    }

#ifdef TLS_DEBUG
    {
        u32 k;
        if (flag&A_TLS_SECRET_WRITE)
            printf("init cipher write:\n", (flag&A_TLS_SECRET_WRITE));
        else
            printf("init cipher read:\n");
        printf("cipher_key:%d\n", key_len);
        for(k=0;k<key_len;k++)
        {
            printf("%02X",((u8*)cipher_key)[k]);
        }
        printf("\n");
        printf("cipher_iv:%d\n",iv_len);
        for(k=0;k<iv_len;k++)
        {
            printf("%02X",((u8*)cipher_iv)[k]);
        }
        printf("\n");
    }
#endif

    if (!EVP_CipherInit_ex(ctx, cipher->c, NULL, cipher_key, NULL, !!(flag&A_TLS_SECRET_WRITE))
        || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, iv_len, cipher_iv))
    {
        printf("tls init cipher err\n");
        return A_TLS_ERR;
    }

    return A_TLS_OK;
}

s32 d_tls_enc_gcm(a_tls_t *tls, crypto_info_t *info)
{
    u8 *p     = info->p;
    u32 p_len = info->p_len, i;
    u8 *start = p-8;
    u8 add[13];
    s32 ret;

    memcpy(add, tls->seq[1], 8);
    add[8] = info->type;
    add[9] = tls->handshake_version>>8;
    add[10]= tls->handshake_version&0xff;
    add[11] = (p_len+8)>>8;
    add[12] = (p_len+8)&0xff;
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("GCM enc add:\n");
        for(k=0;k<13;k++)
            printf("%02X", add[k]);
        printf("\n");
    }
#endif
    /*Set ADD for GCM*/
    if (EVP_CIPHER_CTX_ctrl(tls->write_ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(add), add) <= 0)
        return A_TLS_ERR;

    ret = EVP_Cipher(tls->write_ctx, start, start, 8 + p_len + EVP_GCM_TLS_TAG_LEN);
    if (ret <=0 ) {
        printf("ENC err\n");
        return A_TLS_ERR;
    }
    info->c = start;
    info->c_len = p_len + 8 + EVP_GCM_TLS_TAG_LEN;

    /*update write seq*/
    for (i = 7; (s32)i >= 0; i--) {
        ++tls->seq[1][i];
        if(tls->seq[1][i] != 0) break;
    }
    return A_TLS_OK;
}

s32 d_tls_dec_gcm(a_tls_t *tls, crypto_info_t *info)
{
    u8 *c       = info->c;
    u32 c_len   = info->c_len;
    u8 add[13];
    s32 i, out_len;

    memcpy(add, tls->seq[0], 8);
    add[8] = info->type;
    add[9] = tls->handshake_version>>8;
    add[10]= tls->handshake_version&0xff;
    add[11] = c_len>>8;
    add[12] = c_len&0xff;

#ifdef TLS_DEBUG
        {
            u32 k;
            printf("GCM dec add:\n");
            for(k=0;k<13;k++)
                printf("%02X", add[k]);
            printf("\n");
        }
#endif
        /*Set ADD for GCM*/
    EVP_CIPHER_CTX_ctrl(tls->read_ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(add), add);

    out_len = EVP_Cipher(tls->read_ctx, c, c, c_len);
    if (out_len <= 0)
    {
        printf("EVP_Cipher err\n");
        return A_TLS_ERR;
    }

    info->p = c + 8;
    info->p_len = out_len;

    /*update write seq*/
    for (i = 7; i >= 0; i--)
    {
        ++tls->seq[0][i];
        if (tls->seq[0][i] != 0)
            break;
    }

    return A_TLS_OK;
}

s32 d_crypto_phash(const EVP_MD *md, u8 *sec, int sec_len, u8 *seed, u32 seed_len, u8 *out, u32 olen)
{
    u8 *p = NULL, A1[A_CRYPTO_MAX_MD_LEN];
    u32 out_len;

    p = malloc(A_CRYPTO_MAX_MD_LEN + seed_len);
    if (unlikely(NULL == p))
    {
        return A_TLS_ERR;
    }

    HMAC(md, sec, sec_len, seed, seed_len, A1, &out_len);  // outlen == hash_size

    for (;;)
    {
        memcpy(p, A1, out_len);
        memcpy(p + out_len, seed, seed_len);

        if (olen > out_len)
        {
            HMAC(md, sec, sec_len, p, out_len + seed_len, out, &out_len);

            out  += out_len;
            olen -= out_len;

            HMAC(md, sec, sec_len, A1, out_len, A1, &out_len);
        }
        else
        {
            HMAC(md, sec, sec_len, p, out_len + seed_len, A1, &out_len);

            memcpy(out, A1, olen);
            break;
        }
    }

    free(p);
    return A_TLS_OK;
}

s32 d_crypto_gen_ec_pub(d_group_t *group, u8 *prv, u8 *pub, u32 *prv_len, u32 *pub_len)
{
    s32 ret = A_TLS_ERR;
    const EC_POINT *basepoint;
    EC_POINT *pub_key = NULL;
    BN_CTX *ctx;
    BIGNUM *priv_key;
    BIGNUM *order;

    ctx      = BN_CTX_new();
    priv_key = BN_new();
    order    = BN_new();

    if (ctx      == NULL ||
        priv_key == NULL || 
        order    == NULL)
    {
        goto err;
    }

    basepoint = EC_GROUP_get0_generator(group->group);
    if (basepoint == NULL)
    {
        printf("err a_crypto_gen_ec_pub %d group:%p\n",__LINE__, group->group);
        goto err;
    }

    /*Alloc result's memory*/
    pub_key = EC_POINT_new(group->group);
    if (pub_key == NULL)
    {
        printf("err a_crypto_gen_ec_pub %d\n",__LINE__);
        goto err;
    }

    /*Alloc priv_key's memory*/
    if (!EC_GROUP_get_order(group->group, order, ctx) || 
        !BN_rand_range(priv_key, order))
    {
        printf("err a_crypto_gen_ec_pub %d\n",__LINE__);
        goto err;
    }

    /*do  "priv_key*basepoint" */
    if (!EC_POINT_mul(
        group->group,
        pub_key,
        NULL,/*generator scale*/
        basepoint,
        priv_key,
        ctx))
    {
        printf("err a_crypto_gen_ec_pub %d\n",__LINE__);
        goto err;
    }

    //EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx);

    *pub_len = group->field_len * 2 + 1;
    *prv_len = BN_num_bytes(priv_key);

    if (*pub_len > D_TLS_ECDH_PUB_MAX_LEN ||
        *prv_len > D_TLS_ECDH_PRV_MAX_LEN)
        goto err;

    if (prv == NULL || 
        pub == NULL)
        goto err;

    if(!BN_bn2bin(priv_key, prv))
        goto err;

    EC_POINT_point2oct(
        group->group, 
        pub_key, 
        POINT_CONVERSION_UNCOMPRESSED,
        pub, 
        *pub_len, 
        NULL);

    ret = A_TLS_OK;
end:
    if (ctx) {
        BN_CTX_free(ctx);
    }

    if (priv_key) {
        BN_free(priv_key);
    }

    if (order) {
        BN_free(order);
    }

    return ret;

err:
    ret = A_TLS_ERR;
    goto end;
}

s32 d_tls_gen_master_secret(a_tls_t *tls, u8 *pms, u32 pms_len)
{
    u8 buf[A_TLS_MASTER_KEY_BUF_LEN] = {0};
    //
    u8 *p = buf;
    memcpy(p, A_TLS_MASTER_SECRET_CONST, A_TLS_MASTER_SECRET_CONST_LEN);
    p += A_TLS_MASTER_SECRET_CONST_LEN;
    //
    memcpy(p, tls->handshake->clnt_random, A_TLS_RAND_SIZE);
    p += A_TLS_RAND_SIZE;
    //
    memcpy(p, tls->handshake->srv_random, A_TLS_RAND_SIZE);

    memset(tls->master_secret, 0, sizeof(tls->master_secret));

    d_crypto_phash(tls->d_cipher->md, pms, pms_len, buf, sizeof(buf), tls->master_secret, A_TLS_MASTER_KEY_LEN);
    return A_TLS_OK;
}

s32 a_crypto_do_ec_mul(d_group_t *group, u8 *scale, u32 scale_len, u8 *f_point, u32 f_point_len, u8 *out)
{
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL, *r = NULL;
    BIGNUM *s = NULL;
    s32 ret;

    ctx     = BN_CTX_new();
    s       = BN_new();
    pub_key = EC_POINT_new(group->group);
    r       = EC_POINT_new(group->group);

    if (!ctx
        || !s
        || !pub_key
        || !r) {
            goto err;
    }

    if(!BN_bin2bn(scale, scale_len, s)) {
        goto err;
    }

    if(!EC_POINT_oct2point(group->group, pub_key, f_point, f_point_len, ctx))
    {
        goto err;
    }

    if (!EC_POINT_mul(
        group->group,
        r,
        NULL,/*generator scale*/
        pub_key,
        s,
        ctx)) {
            goto err;
    }
    if (!EC_POINT_point2oct(group->group, r, POINT_CONVERSION_UNCOMPRESSED,
        out, group->field_len * 2 + 1, NULL))
        goto err;

    ret = A_TLS_OK;

free:
    if (ctx) {
        BN_CTX_free(ctx);
    }

    if (s) {
        BN_free(s);
    }

    if (pub_key) {
        EC_POINT_free(pub_key);
    }

    if (r) {
        EC_POINT_free(r);
    }
    return ret;
err:
    ret = A_TLS_ERR;
    goto free;
}

s32 a_crypto_calc_ec_shared(d_group_t *group, u8 *scale, u32 scale_len, u8 *f_point, u32 f_point_len, u8 *out, u32 *out_len)
{
    u8 tmp[A_CRYPTO_MAX_EC_PUB_LEN];

#ifdef TLS_DEBUG
    {
        u32 i;
        printf("ec scale\n");
        for(i=0;i<scale_len;i++)
        {
            printf("%02X", scale[i]);
        }
        printf("\n");
    }
#endif
    if (a_crypto_do_ec_mul(group, scale, scale_len, f_point, f_point_len, tmp)
        != A_TLS_OK)
    {
        return A_TLS_ERR;
    }
#ifdef TLS_DEBUG
    {
        u32 i;
        printf("after ec\n");
        for(i=0;i<32*2+1;i++)
        {
            printf("%02X", tmp[i]);
        }
        printf("\n");
    }
#endif

    /*Only get X*/
    memcpy(out, tmp + 1, group->field_len);
    *out_len = group->field_len;
    return A_TLS_OK;
}
