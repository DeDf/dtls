
#include "d_tls.h"

extern d_cipher_t d_ciphers[D_TLS_MAX_CIPHER];

s32 d_tls_do_read(a_tls_t *tls, u8 *data, s32 data_len)
{
    s32 retlen = 0;
    u8 *p = data;
    s32 toread = data_len;
    s32 nread;

    if (data_len == 0)
        return retlen;

L_loop:
    nread = recv(tls->fd, p, toread, 0);
    if (nread <= 0)
        return nread;
    retlen += nread;

    if (nread < toread)
    {
        p += nread;
        toread -= nread;
        goto L_loop;
    }

    return retlen;
}

s32 d_tls_do_write(a_tls_t *tls, u8 *data, s32 data_len)
{
    s32 retlen = 0;
    u8 *p = data;
    s32 towrite = data_len;
    s32 nwrite;

    if (data_len == 0)
        return retlen;

L_loop:
    nwrite = send(tls->fd, p, data_len, 0);
    if (nwrite <= 0)
        return nwrite;
    retlen += nwrite;

    if (nwrite < towrite)
    {
        p += towrite;
        towrite -= nwrite;
        goto L_loop;
    }

    return retlen;
}

s32 d_tls_save_hs(a_tls_t *tls, u8 *data, s32 data_len)
{
    a_tls_handshake_t *hs = tls->handshake;
    u32 max_size = hs->digest_max_size;

    //printf("a_tls_save_hs() sum:%d, len:%d\n", hs->diget_offset, data_len);

    if (unlikely(hs->digest_offset + data_len > max_size))
    {
        u8 *new_digest_cache = NULL;

        max_size += 4096;
        new_digest_cache = malloc(max_size);
        if (new_digest_cache == NULL)
        {
            printf("tls realloc digest err\n");
            return A_TLS_ERR;
        }
        memcpy(new_digest_cache, hs->digest_cache, hs->digest_offset);
        free(hs->digest_cache);

        hs->digest_cache = new_digest_cache;
        hs->digest_max_size = max_size;
    }

    memcpy(hs->digest_cache + hs->digest_offset, data, data_len);
    hs->digest_offset += data_len;

    return A_TLS_OK;
}

u8 *d_tls_read_record_body(a_tls_t *tls, u8 type, s32 *p_body_len)
{
    s32 body_len;
    s32 nread;
    u8 *p = tls->tmp_msg_buf;
    u16 version;

    if (!p_body_len)
        goto L_error;
    *p_body_len = 0;

    nread = d_tls_do_read(tls, p, A_TLS_HEAD_LEN);
    if (nread != A_TLS_HEAD_LEN)
    {
        printf("d_tls_read_record_body() read record head error! len:%d\n", nread);
        goto L_error;
    }

    if (*p++ != type)
    {
        printf("d_tls_read_record_body() record type(%d) -> err(%d)\n", type, *p);
        goto L_error;
    }

    n2s(p, version);
    if (version != A_TLS_TLS_1_2_VERSION)
    {
        printf("d_tls_read_record_body() record version err:%d\n", version);
        goto L_error;
    }

    n2s(p, body_len);
    if (body_len > D_TLS_MSG_MAX_LEN - A_TLS_HEAD_LEN)
        goto L_error;

    nread = d_tls_do_read(tls, p, body_len);
    if (nread != body_len)
    {
        goto L_error;
    }

    if (type == D_TLS_RT_HANDHSHAKE)
    {
        if (d_tls_save_hs(tls, p, body_len) != A_TLS_OK)
        {
            printf("a_tls_save_hs() err! len:%d\n", body_len);
            goto L_error;
        }
    }

    *p_body_len = body_len;
    return p;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return NULL;
}

s32 d_tls_send_hs(a_tls_t *tls, u8 *data, s32 data_len)
{
    u8 *p = data - 5;
    s32 tosend = data_len + 5;
    s32 nsend;

    *p++ = D_TLS_RT_HANDHSHAKE;
    s2n(tls->handshake_version, p);
    s2n(data_len, p);

    nsend = d_tls_do_write(tls, data - 5, tosend);
    if (nsend == tosend)
        return A_TLS_OK;

    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 d_tls_construct_clnt_hello(a_tls_t *tls, u8 *p)
{
    u8 *op = p;
    s16 ciphers_len;
    u16 version;
    s32 i;

    // A_TLS_TLS_1_2_VERSION = 0x0303
    p[0] = 3;
    p[1] = 3;
    n2s(p, version);

    // todo: random
    memset(p, 0xcc, 32);  // DeDf
    memcpy(tls->handshake->clnt_random, p, 32);
    p += 32;

    /*session id len = 0*/
    *p++ = 0;

    ciphers_len = D_TLS_MAX_CIPHER;
    s2n(ciphers_len * 2, p);

    for(i = 0; i < ciphers_len; i++)
    {
        u16 tls_nid = (u16)d_ciphers[i].tls_nid;
        u8 *c = (u8 *)&tls_nid;

        *p++ = c[1];
        *p++ = c[0];
    }

    /*compress : NULL*/
    *p++ = 1;
    *p++ = 0;

    /* extension */
    if(likely(1))
    {
        u8 *pExtLen = p;
        u16 ExtLen;
        s32 len;

        p += 2;
        
        len = d_tls_ext_gen_server_name(tls, p);
        p += len;
        len = d_tls_ext_gen_support_gp(tls, p);
        p += len;
        len = a_tls_ext_gen_sig(tls, p);
        p += len;

        ExtLen = (u16)(p - pExtLen - 2);
        *(u16*)pExtLen = _byteswap_ushort(ExtLen);
    }

    return (s32)(p - op);
}

s32 d_tls_select_cipher(a_tls_t *tls)
{
    u16 cipher_nid = tls->cipher_nid;
    d_cipher_t *c = NULL;
    ULONG i;

    for (i = 0; i < D_TLS_MAX_CIPHER; i++)
    {
        if (cipher_nid == d_ciphers[i].tls_nid)
        {
            c = &d_ciphers[i];
        }
    }

    if (c)
    {
        c->md = EVP_get_digestbynid(c->md_nid);
        c->c = EVP_get_cipherbynid(c->openssl_nid);
        printf("   server select ciphers : %s\n", c->name);
        tls->d_cipher = c;
        return A_TLS_OK;
    }

    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 a_tls_process_cke_ecdh(void *arg, u8 *in, u32 in_len)
{
    u32 pms_len;
    u8 *p = in, pms[A_CRYPTO_MAX_EC_PUB_LEN/2];
    a_tls_t *tls = arg;
    a_tls_handshake_t *hs = tls->handshake;

    in_len -= 1;

    if (*p++ != in_len) {
        printf("tls ecdhe len dec err\n");
        return A_TLS_ERR;
    }

    a_crypto_calc_ec_shared(tls->d_group,
        hs->self_ecdh_prv,
        hs->self_ecdh_prv_len,
        p,
        in_len,
        pms, &pms_len);
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("ecdhe pms %d\n",pms_len);
        for(k=0;k<pms_len;k++)
            printf("%02X",pms[k]);
        printf("\n");
    }
#endif
    d_tls_gen_master_secret(tls, pms, pms_len);
#ifdef TLS_DEBUG
    {
        u32 k;
        printf("master key:%d\n",A_TLS_MASTER_KEY_LEN);
        for(k=0;k<A_TLS_MASTER_KEY_LEN;k++)
            printf("%02X", tls->master_secret[k]);
        printf("\n");
    }
#endif

    return A_TLS_OK;
}

void d_tls_free_hs(a_tls_handshake_t *hs)
{
    if (hs)
    {
        if (hs->digest_cache)
            free(hs->digest_cache);

        free(hs);
    }
}
