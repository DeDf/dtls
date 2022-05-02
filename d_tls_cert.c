
#include "d_tls.h"

X509_STORE *g_SslCertStore;  // ����X509_STORE�����洢֤����

// ----------- Need free -----------
// if (g_SslCertStore)
// {
//     X509_STORE_free(g_SslCertStore);
//     g_SslCertStore = NULL;
// }

// if (tls->cert)
// {
//     X509_free(tls->cert);
//     tls->cert = NULL;
// }

// if (tls->pkey)
// {
//     EVP_PKEY_free(tls->pkey);
//     tls->pkey = NULL;
// }
// ---------------------------------

ULONG addWinCertToSslStore(X509_STORE *SslCertStore, const char *subSystemName);

VOID InitSslCertStore()
{
    if (!g_SslCertStore)
    {
        X509_STORE * SslCertStore = X509_STORE_new();  //��ʼ��֤����

        if (SslCertStore)
        {
            //ͨ����������������ε�֤�������������ROOT�Ǹ�֤��
            addWinCertToSslStore(SslCertStore, "ROOT");
            g_SslCertStore = SslCertStore;
        }
    }
}

ULONG addWinCertToSslStore(X509_STORE *SslCertStore, const char *subSystemName)
{
    ULONG nCerts = 0;
    HCERTSTORE hWinCertStore = CertOpenSystemStoreA(0, subSystemName);
    if (hWinCertStore)
    {
        PCCERT_CONTEXT windowsCertificate = NULL;
        while (windowsCertificate = CertEnumCertificatesInStore(hWinCertStore, windowsCertificate))
        {
            X509 *opensslCertificate = d2i_X509(NULL, 
                    (unsigned char **)&windowsCertificate->pbCertEncoded,
                    windowsCertificate->cbCertEncoded);

            if (opensslCertificate)
            {
                X509_STORE_add_cert(SslCertStore, opensslCertificate);
                X509_free(opensslCertificate);
            }

            ++nCerts;
        }

        CertCloseStore(hWinCertStore, 0);
    }

    return nCerts;
}

int VerifyCerts(a_tls_t *tls)
{
    int nX509Verify = -1;
    X509_STORE_CTX *ctx = NULL;      //֤����������
    STACK_OF(X509) *sk = NULL;
    X509 *cert;
    ULONG i;

    if (!g_SslCertStore)
        InitSslCertStore();

    ctx = X509_STORE_CTX_new();  //Ϊ֤���������ķ����ڴ�
    if (ctx)
    {
        sk = sk_X509_new_null();
        if (sk)
        {
            for (i = 0; i < CERT_SUM_MAX; i++)
            {
                if (!tls->cert_chain[i].buf)
                    break;

                cert = d2i_X509(NULL, &tls->cert_chain[i].buf, tls->cert_chain[i].len);
                if (cert)
                {
                    if (!sk_X509_push(sk, cert))
                    {
                        X509_free(cert);
                        goto L_Exit;
                    }
                }
            }

            cert = sk_X509_value(sk, 0);
            if (cert)
            {
                // ��ʼ��֤���������ģ�SslCertStore��֤��⣬cert��Ҫ����֤��֤��, sk��֤����
                X509_STORE_CTX_init(ctx,g_SslCertStore,cert,sk);

                // ��֤����֤֮ǰ������ͨ������flags��ȷ����֤������
                // flags��������x509_vfy.h������/* Certificate verify flags */ 
                //X509_STORE_CTX_set_flags(ctx,flags);

                //��֤֤�飬���ݷ���ֵ����ȷ��X509֤���Ƿ���Ч
                nX509Verify = X509_verify_cert(ctx);
                if (nX509Verify == 1)
                {
                    tls->cert = cert;
                    tls->p_pub_key = X509_get_pubkey(cert);
                }
                else
                {
                    long nCode = X509_STORE_CTX_get_error(ctx);
                    const char * pChError = X509_verify_cert_error_string(nCode);
                    printf("   nX509Verify(%d) : %s !\n", nCode, pChError);
                    if (nCode == 18)      // self sign cert  // DeDf
                    {
                        tls->cert = cert;
                        tls->p_pub_key = X509_get_pubkey(cert);
                        nX509Verify = 1;
                    }
                }
            }
L_Exit:
            sk_X509_free(sk);
        }

        X509_STORE_CTX_free(ctx);
    }

    return nX509Verify;
}

// pkey = X509_get_pubkey(cert);