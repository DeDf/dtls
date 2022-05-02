
#include "d_tls.h"

// ------------------------------------------------------

#pragma pack(push)
#pragma pack(1)
typedef struct d_tls_server_name
{
    u16 type;
    u16 len;
    u16 name_list_len;
    u8  name_type;
    u16 name_len;
    u8  name[0];

} d_tls_server_name_t;
#pragma pack(pop)

s32 d_tls_ext_gen_server_name(a_tls_t *tls, u8 *ext)
{
    s32 ret = 0;
    d_tls_server_name_t *pSerName = (d_tls_server_name_t *)ext;

    if (tls->HostNameLen == 0)
        return ret;

    pSerName->type          = _byteswap_ushort(A_TLS_EXT_SRV_NAME);
    pSerName->len           = _byteswap_ushort(tls->HostNameLen + 5);
    pSerName->name_list_len = _byteswap_ushort(tls->HostNameLen + 3);
    pSerName->name_type     = 0;
    pSerName->name_len      = _byteswap_ushort(tls->HostNameLen);
    memcpy(pSerName->name, tls->chHostName, tls->HostNameLen);

    return (s32)tls->HostNameLen + 9;
}

// ------------------------------------------------------

extern d_group_t d_groups[D_TLS_MAX_GROUP];

typedef struct d_tls_support_gp
{
    u16 type;
    u16 len;
    u16 gp_list_len;
    u16 gp[0];

} d_tls_support_gp_t;

s32 d_tls_ext_gen_support_gp(a_tls_t *tls, u8 *ext)
{
    s32 ret = 0;
    u16 sg_len = sizeof(d_groups)/sizeof(d_group_t);
    d_tls_support_gp_t *pSupGP = (d_tls_support_gp_t *)ext;
    u8 *p = (u8 *)&pSupGP->gp;
    d_group_t *p_group;
    u32 i;

    pSupGP->type        = _byteswap_ushort(A_TLS_EXT_SUPPORT_GP);
    pSupGP->len         = _byteswap_ushort(sg_len * 2 + 2);
    pSupGP->gp_list_len = _byteswap_ushort(sg_len * 2);

    p_group = d_groups;
    for(i = 0; i < sg_len; i++)
    {
        u16 tls_nid = p_group[i].tls_nid;
        u8 *c = (u8 *)&tls_nid;

        *p++ = c[1];
        *p++ = c[0];
    }

    return (s32)(p - ext);
}

// ------------------------------------------------------

extern sigalg_pair_t d_sigalg_pair[D_TLS_MAX_SIG_ALG];

typedef struct d_tls_sig
{
    u16 type;
    u16 len;
    u16 sig_list_len;
    u16 sig[0];

} d_tls_sig_t;

s32 a_tls_ext_gen_sig(a_tls_t *tls, u8 *ext)
{
    s32 ret = 0;
    u16 sp_len = sizeof(d_sigalg_pair)/sizeof(sigalg_pair_t);
    d_tls_sig_t *pSig = (d_tls_sig_t *)ext;
    u8 *p = (u8 *)&pSig->sig;
    sigalg_pair_t *sp;
    u32 i;

    pSig->type         = _byteswap_ushort(A_TLS_EXT_SIG_ALG);
    pSig->len          = _byteswap_ushort(sp_len * 2 + 2);
    pSig->sig_list_len = _byteswap_ushort(sp_len * 2);

    sp = d_sigalg_pair;
    for(i = 0; i < sp_len; i++)
    {
        u16 tls_id = sp[i].tls_nid;
        u8 *c = (u8 *)&tls_id;

        *p++ = c[1];
        *p++ = c[0];
    }

    return (s32)(p - ext);
}

