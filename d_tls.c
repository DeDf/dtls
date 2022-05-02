#include "d_tls.h"

extern sigalg_pair_t d_sigalg_pair[D_TLS_MAX_SIG_ALG];
extern d_group_t d_groups[D_TLS_MAX_GROUP];

s32 d_tls_init(a_tls_t *tls);
s32 d_tls_send_client_hello(a_tls_t *tls);
s32 d_tls_get_srv_hello(a_tls_t *tls);
s32 d_tls_get_srv_cert(a_tls_t *tls);
s32 d_tls_get_srv_ke(a_tls_t *tls);
s32 d_tls_get_srv_hello_done(a_tls_t *tls);
s32 d_tls_send_client_ke(a_tls_t *tls);
s32 d_tls_send_client_ccs(a_tls_t *tls);
s32 d_tls_send_client_finished(a_tls_t *tls);
s32 d_tls_get_srv_ccs(a_tls_t *tls);
s32 d_tls_get_srv_finished(a_tls_t *tls);

state_func d_tls_state_proc[D_TLS_STATE_MAX] =
{
    d_tls_init,
    d_tls_send_client_hello,
    d_tls_get_srv_hello,
    d_tls_get_srv_cert,
    d_tls_get_srv_ke,
    d_tls_get_srv_hello_done,
    d_tls_send_client_ke,
    d_tls_send_client_ccs,
    d_tls_send_client_finished,
    d_tls_get_srv_ccs,
    d_tls_get_srv_finished,
};

// ------------------------------------------------------------

a_tls_t *d_tls_new(int sock, char *pchHostName)
{
    ULONG i;
    a_tls_t *tls = malloc(sizeof(a_tls_t));
    if (tls)
    {
        USHORT HostNameLen;
        memset(tls, 0, sizeof(a_tls_t));

        tls->state      = D_TLS_STATE_INIT;
        tls->state_proc = d_tls_state_proc;
        tls->d_group = NULL;
        tls->version    = 0x0303;
        tls->fd = sock;

        HostNameLen = strlen(pchHostName);
        if (HostNameLen > 1024 - 1)
            HostNameLen = 1024 - 1;

        memcpy(tls->chHostName, pchHostName, HostNameLen);
        tls->HostNameLen = HostNameLen;
    }

    for(i = 0; i < sizeof(d_groups)/sizeof(d_group_t); i++)
    {
        d_groups[i].group = EC_GROUP_new_by_curve_name(d_groups[i].openssl_nid);
        if (d_groups[i].group) {
            d_groups[i].field_len = (EC_GROUP_get_degree(d_groups[i].group) + 7) / 8;  // 获取椭圆曲线密钥长度
        }
    }

    return tls;
}

void d_tls_free(a_tls_t *tls)
{
    u32 i;

    //------------ DeDf ------------
    if (!tls)
        return;

    for (i = 0; i < CERT_SUM_MAX; i++)
    {
        if (!tls->cert_chain[i].buf)
            break;

        free(tls->cert_chain[i].buf);
        tls->cert_chain[i].buf = NULL;
        tls->cert_chain[i].len = 0;
    }
    //------------------------------

    if (tls->handshake) {
        d_tls_free_hs(tls->handshake);
        tls->handshake = NULL;
    }

    if (tls->write_ctx) {
        EVP_CIPHER_CTX_free(tls->write_ctx);
    }

    if (tls->read_ctx) {
        EVP_CIPHER_CTX_free(tls->read_ctx);
    }

    free(tls);
}

s32 d_tls_handshake(a_tls_t *tls)  // done!
{
    s32 ret;

    for (; tls->state < D_TLS_STATE_ESTABLISH; )
    {
        ret = tls->state_proc[tls->state](tls);
        if (ret)
            break;
    }

    if (tls->handshake)
    {
        d_tls_free_hs(tls->handshake);
        tls->handshake = NULL;
    }

    return ret;
}

// ------------------------------------------------------------

s32 d_tls_init(a_tls_t *tls)  // done!
{
    tls->handshake_version = 0x0303;

    tls->handshake = malloc(sizeof(a_tls_handshake_t));
    if (tls->handshake)
    {
        memset(tls->handshake, 0, sizeof(a_tls_handshake_t));

        tls->handshake->digest_cache = malloc(8192);
        if (tls->handshake->digest_cache)
        {
            tls->handshake->digest_max_size = 8192;
            tls->state = D_TLS_STATE_SND_CLNT_HELLO;

            return A_TLS_OK;
        }

        free(tls->handshake);
        tls->handshake = NULL;
    }

    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

/*Client start here*/
s32 d_tls_send_client_hello(a_tls_t *tls)
{
    u8 *p = tls->tmp_msg_buf + 5, *l;
    s32 len;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    *p++ = D_TLS_HS_CLNT_HELLO;
    l = p;
    p += 3;

    len = d_tls_construct_clnt_hello(tls, p);
    if (len <= 0) {
        return A_TLS_ERR;
    }

    l2n3(len, l);
    len += 4;

    tls->state = D_TLS_STATE_GET_SRV_HELLO;

    p = tls->tmp_msg_buf + 5;
    if (d_tls_save_hs(tls, p, len) != A_TLS_OK)
        return A_TLS_ERR;

    return d_tls_send_hs(tls, p, len);
}

s32 d_tls_get_srv_hello(a_tls_t *tls)
{
    u8 *data;
    s32 data_len;
    u8 *p;
    s32 HsMsgLen;
    u16 version;
    u8 SessIDLen;
    u16 cipher_nid;
    u8 compress_method;
    u16 ext_len;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    data = d_tls_read_record_body(tls, D_TLS_RT_HANDHSHAKE, &data_len);
    if (!data || data_len < 42)
        goto L_error;

    p = data;
    if (*p++ != D_TLS_HS_SRV_HELLO)
        goto L_error;

    n2l3(p, HsMsgLen);
    if (HsMsgLen != data_len - 4)
        goto L_error;

    n2s(p, version);
    if (version != 0x0303)  // tls1.2
        goto L_error;

    memcpy(tls->handshake->srv_random, p, 32);
    p += 32;

    SessIDLen = *p++;
    if (SessIDLen > data_len - (p-data) - 3)
        goto L_error;
    p += SessIDLen;

    n2s(p, cipher_nid);
    tls->cipher_nid = cipher_nid;
    if (d_tls_select_cipher(tls) != A_TLS_OK)
    {
        printf("a_tls_cipher_get() err\n");
        return A_TLS_ERR;
    }

    compress_method = *p++;

    if (data_len - (p-data) >= 2)
    {
        n2s(p, ext_len);

        if (ext_len != data_len - (p-data))
            goto L_error;
    }

    tls->state = D_TLS_STATE_GET_SRV_CERT;
    return A_TLS_OK;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 d_tls_get_srv_cert(a_tls_t *tls)
{
    u8 *data;
    s32 data_len;
    u8 *p;
    u32 HsMsgLen;
    u32 CertMsgLen;
    u32 CertLenSum = 0;
    u32 i;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    data = d_tls_read_record_body(tls, D_TLS_RT_HANDHSHAKE, &data_len);
    if (!data || !data_len)
        goto L_error;

    p = data;
    if (*p++ != D_TLS_HS_CERT)
        goto L_error;

    n2l3(p, HsMsgLen);
    if ((HsMsgLen != data_len - 4) || HsMsgLen < 0x100)
        goto L_error;

    n2l3(p, CertMsgLen);
    if ((CertMsgLen != HsMsgLen - 3) || CertMsgLen < 0x100)
        goto L_error;

    for (i = 0; i < CERT_SUM_MAX; i++)
    {
        u8 *pCert;
        u32 len;
        n2l3(p, len);
        CertLenSum += len + 3;
        if (len < 0x100 || CertLenSum > CertMsgLen)
            goto L_error;

        pCert = malloc(len);
        if (!pCert)
            goto L_error;

        memcpy(pCert, p, len);
        tls->cert_chain[i].buf = pCert;
        tls->cert_chain[i].len = len;

        if (CertLenSum == CertMsgLen)
            break;
        else
            p += len;
    }

    if (VerifyCerts(tls) != 1)
        goto L_error;

    tls->state = D_TLS_STATE_GET_SRV_KE;
    return A_TLS_OK;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 d_tls_get_srv_ke(a_tls_t *tls)
{
    s32 ret;
    u8 *data;
    s32 data_len;
    u8 *p;
    u32 HsMsgLen;
    a_tls_handshake_t *hs = tls->handshake;
    u16 group_nid;
    u8 ecdh_pub_len;
    u16 sign_alg_nid;
    ULONG i;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    data = d_tls_read_record_body(tls, D_TLS_RT_HANDHSHAKE, &data_len);
    if (!data || data_len < 0x50) // (data_len < 333)
        goto L_error;

    p = data;
    if (*p++ != D_TLS_HS_SRV_KEYEXCHANGE)
        goto L_error;

    n2l3(p, HsMsgLen);

    if (HsMsgLen + 4 != data_len)
        goto L_error;

    if (*p++ != 3)
        goto L_error;

    n2s(p, group_nid);
    for (i = 0; i < D_TLS_MAX_GROUP; i++)
    {
        if (d_groups[i].tls_nid == group_nid)
        {
            tls->d_group = &d_groups[i];
            break;
        }
    }
    if (i == D_TLS_MAX_GROUP)
        goto L_error;
    
    printf("   server select group : %s\n", d_groups[i].name);

    ecdh_pub_len = *p++;
    if (ecdh_pub_len > D_TLS_ECDH_PUB_LEN)
        goto L_error;
    p += ecdh_pub_len;

    n2s(p, sign_alg_nid);
    for (i = 0; i < D_TLS_MAX_SIG_ALG; i++)
    {
        if (d_sigalg_pair[i].tls_nid == sign_alg_nid)
            break;
    }
    if (i == D_TLS_MAX_SIG_ALG)
        goto L_error;
    printf("   server select sig_alg_pair : %s\n", d_sigalg_pair[i].name);

    if (sign_alg_nid == 0x0804)
    {
        ret = d_crypto_verify_rsa_sign(tls, EVP_sha256(), p-2-ecdh_pub_len-4, p);
    }
    else if (sign_alg_nid == 0x0805)
    {
        ret = d_crypto_verify_rsa_sign(tls, EVP_sha384(), p-2-ecdh_pub_len-4, p);
    }
    else if (sign_alg_nid == 0x0403)
    {
        ret = d_crypto_verify_ec_sign(tls, EVP_sha256(), p-2-ecdh_pub_len-4, p);
    }
    if (ret)
        goto L_error;

    if (tls->d_group->openssl_nid == NID_X25519)
    {

    }
    else
    {
    d_crypto_gen_ec_pub(
        tls->d_group,
        hs->self_ecdh_prv, hs->self_ecdh_pub,
        &hs->self_ecdh_prv_len, &hs->self_ecdh_pub_len);

    a_tls_process_cke_ecdh(tls, p-2-ecdh_pub_len-1, ecdh_pub_len+1);
    }

    tls->state = D_TLS_STATE_GET_SRV_HELLO_DONE;
    return A_TLS_OK;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 d_tls_get_srv_hello_done(a_tls_t *tls)
{
    u8 *data;
    s32 data_len;
    u8 *p;
    s32 HsMsgLen;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    data = d_tls_read_record_body(tls, D_TLS_RT_HANDHSHAKE, &data_len);
    if (!data || data_len != 4)
        goto L_error;

    p = data;
    if (*p++ != D_TLS_HS_SRV_HELLO_DONE)
        goto L_error;

    n2l3(p, HsMsgLen);
    if (HsMsgLen != 0)
        goto L_error;

    tls->state = D_TLS_STATE_SND_CLNT_KE;
    return A_TLS_OK;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 d_tls_send_client_ke(a_tls_t *tls)
{
    u8 *p = tls->tmp_msg_buf + 5, *l;
    s32 len;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    *p++ = D_TLS_HS_CLNT_KEYEXCHANGE;
    l = p;
    p += 3;

    len = tls->handshake->self_ecdh_pub_len;
    *p++ = len;
    memcpy(p, tls->handshake->self_ecdh_pub, len);

    ++len;
    l2n3(len, l);
    len += 4;

    tls->state = D_TLS_STATE_SND_CLNT_CCS;

    p = tls->tmp_msg_buf + 5;
    if (d_tls_save_hs(tls, p, len) != A_TLS_OK)
        return A_TLS_ERR;

    return d_tls_send_hs(tls, p, len);
}

s32 d_tls_send_client_ccs(a_tls_t *tls)
{
    u8 *p = tls->tmp_msg_buf;
    s32 tosend;
    s32 nsend;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    *p++ = D_TLS_RT_CCS;
    s2n(tls->version, p);
    s2n(1, p);
    *p++ = 1;

    tosend = (s32)(p - tls->tmp_msg_buf);

    nsend = d_tls_do_write(tls, tls->tmp_msg_buf, tosend);
    if (nsend == tosend)
    {
        d_tls_init_cipher_aes_gcm(tls, A_TLS_SECRET_CLNT|A_TLS_SECRET_WRITE);
        tls->state = D_TLS_STATE_SND_CLNT_FINISHED;
        return A_TLS_OK;
    }
    else
    {
        printf("%s() error!\n", __FUNCTION__);
        return A_TLS_ERR;
    }
}

s32 d_tls_send_client_finished(a_tls_t *tls)
{
    u8 *p = tls->tmp_msg_buf + 5 + 8;
    u8 *hs;
    u32 hs_len;
    u8 buf[A_TLS_MD_CLIENT_FINISH_CONST_SIZE + A_CRYPTO_MAX_MD_LEN];
    u32 hash_size;
    crypto_info_t info;
    u32 len;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    hs = tls->handshake->digest_cache;
    hs_len = tls->handshake->digest_offset;

    EVP_Digest(hs, hs_len, buf+A_TLS_MD_CLIENT_FINISH_CONST_SIZE, &hash_size, tls->d_cipher->md, NULL);

    memcpy(buf, A_TLS_MD_CLIENT_FINISH_CONST, A_TLS_MD_CLIENT_FINISH_CONST_SIZE);
    //memcpy(buf + A_TLS_MD_CLIENT_FINISH_CONST_SIZE, hash, hash_size);

    *p++ = D_TLS_HS_FINISHED;
    l2n3(12, p);

    d_crypto_phash(tls->d_cipher->md,
        tls->master_secret, A_TLS_MASTER_KEY_LEN,
        buf, A_TLS_MD_CLIENT_FINISH_CONST_SIZE + hash_size,
         p, 12);

#ifdef TLS_DEBUG
    {
        int k;
        printf("client finished hash:%d\n", hash_size);
        for(k=0;(u32)k<hash_size;k++)
            printf("%02x", buf[k + A_TLS_MD_CLIENT_FINISH_CONST_SIZE]);
        printf("\n");
    }
#endif

    if (d_tls_save_hs(tls, tls->tmp_msg_buf + 5 + 8, 4+12) != A_TLS_OK)
        return A_TLS_ERR;

    info.p     = p - 4;
    info.p_len = 16;
    info.type  = D_TLS_RT_HANDHSHAKE;
    d_tls_enc_gcm(tls, &info);
    len = info.c_len;

    if (len != 40)
    {
        printf("%s() error!\n", __FUNCTION__);
        return A_TLS_ERR;
    }

    tls->state = D_TLS_STATE_GET_SRV_CCS;
    return d_tls_send_hs(tls, tls->tmp_msg_buf + 5, len);
}

s32 d_tls_get_srv_ccs(a_tls_t *tls)
{
    u8 *data;
    s32 data_len;
    u8 *p;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    data = d_tls_read_record_body(tls, D_TLS_RT_CCS, &data_len);
    if (!data || data_len != 1)
        goto L_error;

    p = data;
    if (*p++ != 1)
        goto L_error;

    d_tls_init_cipher_aes_gcm(tls, A_TLS_SECRET_CLNT|A_TLS_SECRET_READ);

    tls->state = D_TLS_STATE_GET_SRV_FINISHED;
    return A_TLS_OK;

L_error:
    printf("%s() error!\n", __FUNCTION__);
    return A_TLS_ERR;
}

s32 d_tls_get_srv_finished(a_tls_t *tls)
{
    u8 *data;
    s32 data_len;
    u8 buf16[16];
    u8 *p;
    u8 *hs;
    u32 hs_len;
    u8 buf[A_TLS_MD_SERVER_FINISH_CONST_SIZE + A_CRYPTO_MAX_MD_LEN];
    u32 hash_size;
    crypto_info_t info;

#ifdef TLS_DEBUG
    printf("d_tls_handshake[%d]: %s()\n", tls->state, __FUNCTION__);
#endif

    data = d_tls_read_record_body(tls, D_TLS_RT_HANDHSHAKE, &data_len);
    if (!data || data_len != 40)
        goto L_error;

    // 最后一个加密握手finished，加了data_len，计算的时候不用、需要减掉
    tls->handshake->digest_offset -= data_len;
    hs = tls->handshake->digest_cache;
    hs_len = tls->handshake->digest_offset;

    EVP_Digest(hs, hs_len, buf+A_TLS_MD_SERVER_FINISH_CONST_SIZE, &hash_size, tls->d_cipher->md, NULL);

    memcpy(buf, A_TLS_MD_SERVER_FINISH_CONST, A_TLS_MD_SERVER_FINISH_CONST_SIZE);
    //memcpy(buf + A_TLS_MD_SERVER_FINISH_CONST_SIZE, hash, hash_size);

#ifdef TLS_DEBUG
    {
        int k;
        printf("srv finished hash:%d\n", hash_size);
        for(k=0;(u32)k<hash_size;k++)
            printf("%02x", buf[k + A_TLS_MD_SERVER_FINISH_CONST_SIZE]);
        printf("\n");
    }
#endif

    p = buf16;
    *p++ = D_TLS_HS_FINISHED;
    l2n3(12, p);

    d_crypto_phash(tls->d_cipher->md,
        tls->master_secret, A_TLS_MASTER_KEY_LEN,
        buf, A_TLS_MD_SERVER_FINISH_CONST_SIZE + hash_size,
        p, 12);
 
    info.c     = data;
    info.c_len = data_len;
    info.type  = D_TLS_RT_HANDHSHAKE;
    d_tls_dec_gcm(tls, &info);

    if (memcmp(buf16, info.p, 16))
    {
L_error:
        printf("%s() error!\n", __FUNCTION__);
        return A_TLS_ERR;
    }

    tls->state = D_TLS_STATE_ESTABLISH;
    return A_TLS_OK;
}

s32 d_tls_write(a_tls_t *tls, u8 *buf, u32 len)
{
    u8 *p;
    s32 send_len, cur_len;
    u32 input_len = len;
    crypto_info_t info;

    if (tls->state != D_TLS_STATE_ESTABLISH) {
        return A_TLS_ERR;
    }

    p = tls->tmp_msg_buf + 5 + 8;

#ifdef TLS_DEBUG
    printf("write data:%d\n", len);
#endif

    while(len)
    {
        cur_len = (len > 16000)?16000:len;

        memcpy(p, buf, cur_len);
        info.p = p;
        info.p_len = cur_len;
        info.type = D_TLS_RT_APPLICATION_DATA;
        d_tls_enc_gcm(tls, &info);

        len -= cur_len;
        buf += cur_len;

        p -= 5 + 8;
        *p++ = D_TLS_RT_APPLICATION_DATA;
        s2n(tls->handshake_version, p);
        s2n(info.c_len, p);

        send_len = d_tls_do_write(tls, info.c - A_TLS_HEAD_LEN, info.c_len + A_TLS_HEAD_LEN);
        if (send_len <= 0) {
            printf("a_tls_do_write error !\n");
            return A_TLS_ERR;
        }
    }

    /*must equal to input length*/
    return input_len;
}

// 返回值是dtls内置buf, 用户需要把数据拷出去
u8 *d_tls_read(a_tls_t *tls, u32 *p_read_len)
{
    u8 *p = NULL;
    u8 *data;
    s32 data_len;
    crypto_info_t info;

#ifdef TLS_DEBUG
    printf("d_tls_read()\n", __FUNCTION__);
#endif

    if (!p_read_len)
        return p;

    if (p_read_len)
        *p_read_len = 0;

    if (tls->state != D_TLS_STATE_ESTABLISH) {
        return p;
    }

    data = d_tls_read_record_body(tls, D_TLS_RT_APPLICATION_DATA, &data_len);
    if (!data || !data_len)
        goto L_error;

    info.c     = data;
    info.c_len = data_len;
    info.type  = D_TLS_RT_APPLICATION_DATA;
    d_tls_dec_gcm(tls, &info);

    *p_read_len = info.p_len;
    p = info.p;

L_error:
    return p;
}