
#include <stdio.h>
#include <winsock2.h>
#include "d_tls.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"crypt32.lib")

unsigned char buf[1024];

void __cdecl __report_rangecheckfailure(void)
{
    ExitProcess(1);
}

int main(int argc, char* argv[])
{
    HANDLE hFile;
    ULONG WriteLen;
    DWORD timeout = 3000;  //3s
    struct sockaddr_in server_addr;
    SOCKET sock      = 0;
    a_tls_t *tls     = NULL;
    u8 *readbuf;
    u32 read_len;
    //char *pchHostName = "www.appinn.com";
    char *pchHostName = "www.baidu.com";
    s32 ret;
    //
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSAStartup() failed!\n");
		exit(-1);
	}

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        perror("socket() failed!\n");
        exit(-1);
    }

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(44444);

//     server_addr.sin_addr.s_addr = inet_addr("172.64.136.22");  // appinn
//     server_addr.sin_port = htons(443);

    server_addr.sin_addr.s_addr = inet_addr("220.181.38.150");  // baidu
    server_addr.sin_port = htons(443);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr))==SOCKET_ERROR)
    {
        printf("connect() failed!\n");
        closesocket(sock);
        exit(-1);
    }

    OPENSSL_config(NULL);
    OpenSSL_add_all_algorithms();

    tls = d_tls_new((int)sock, pchHostName);
    if (tls == NULL)
    {
        printf("d_tls_new error\n");
        exit(-1);
    }

    if (d_tls_handshake(tls) != 0)
    {
        printf("a_tls_handshake error !!\n");
        goto L_error;
    }
    printf("a_tls_handshake success ~\n\n");

    strcpy_s(buf ,sizeof(buf), "GET /img/PCtm_d9c8750bed0b3c7d089fa7d55720d6cf.png HTTP/1.1\r\n\r\n");
    ret = d_tls_write(tls, buf, (u32)strlen(buf));

    printf("Try to read from client.....\n");

    hFile = CreateFileA( "d:\\111",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    for (;;)
    {
        readbuf = d_tls_read(tls, &read_len);
        if (readbuf && read_len)
        {
            WriteFile(hFile, readbuf, read_len, &WriteLen, NULL);
            readbuf[read_len] = 0;
            printf("Recv %d bytes from server ~~~\n%s\n", read_len, readbuf);
        }
        else
            break;
    }

    CloseHandle(hFile);

    if (tls)
        d_tls_free(tls);

L_error:
    if (sock)
        closesocket(sock);

    getchar();
    return 0;
}