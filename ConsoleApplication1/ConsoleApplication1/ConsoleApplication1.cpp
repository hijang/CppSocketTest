// ConsoleApplication1.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include "NetworkTCP.h"
/* 
* openssl 설치 및 설정 변경
* - openssl 패키지 설치 - https://slproweb.com/products/Win32OpenSSL.html (Win32 OpenSSL v1.1.1k)
* - include directory 추가 (프로젝트 > ... 속성 > C/C++ > 일반 > 추가 디렉토리) - C:\Program Files\OpenSSL-Win64\include
* - library directory 추가 (프로젝트 > ... 속성 > 링커 > 일반 > 추가 디렉토리) - C:\Program Files\OpenSSL-Win64\lib
* - library dependancy 추가 (프로젝트 > ... 속성 > 링커 > 입력 > 추가 종속성) - libcrypto.lib;libssl.lib
*/ 
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitCTX(void)
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();        /* Load cryptos, et.al. */
    SSL_load_error_strings();            /* Bring in and register error messages */
    method = SSLv23_client_method();        /* Create new client-method instance */
    ctx = SSL_CTX_new(method);            /* Create new context */
    if (ctx == NULL)
    {
        printf("ctx Error\n");
    }

    /* Cannot fail ??? */
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
{
    std::cout << "Load certifcates. cert: " << CertFile << "/ key: " << KeyFile << std::endl;
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


int main()
{
    SSL_CTX* ctx;
    SSL* ssl;

    std::cout << "Hello World!\n";

    TTcpConnectedPort* TcpConnectedPort = NULL;
    bool retvalue;
    const char* hostname = "172.26.71.209";
    const char* port = "5555";

    ctx = InitCTX();
    LoadCertificates(ctx, "..\\..\\Certificates\\client.crt", "..\\..\\Certificates\\client.key");

    ssl = SSL_new(ctx);

    if ((TcpConnectedPort = OpenTcpConnection(hostname, port)) == NULL)  // Open UDP Network port
    {
        printf("OpenTcpConnection\n");
        return(-1);
    }

    SSL_set_fd(ssl, TcpConnectedPort->ConnectedFd);
    if (SSL_connect(ssl) == -1) {
        printf("Connect failed\n");
        return(-1);
    }

    X509* client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        printf("Client certificate:\n");

        char* str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t issuer: %s\n", str);
        OPENSSL_free(str);

        /* We could do all sorts of certificate verification stuff here before deallocating the certificate. */
        X509_free(client_cert);
    }
    else {
        printf("Client does not have certificate.\n");
    }

    printf("Connected~!\n");
    if (!ssl)
    {
        unsigned int imagesize;
        unsigned char* buff;	/* receive buffer */

        if (ReadDataTcp(TcpConnectedPort, (unsigned char*)&imagesize, sizeof(imagesize)) != sizeof(imagesize)) return(false);

        //imagesize = ntohl(imagesize); // convert image size to host format

        printf("imagesize??? %d\n", imagesize);
        if (imagesize < 0) return false;

        buff = new (std::nothrow) unsigned char[imagesize];
        if (buff == NULL) return false;
        memset(buff, imagesize, 0x00);

        ReadDataTcp(TcpConnectedPort, buff, imagesize);

        printf("%s\n", buff);
        return false;
    }
    else 
    {
        unsigned int imagesize;
        unsigned char* buff;	/* receive buffer */

        SSL_read(ssl, &imagesize, sizeof(imagesize));
        printf("imagesize??? %d\n", imagesize);
        if (imagesize < 0) return false;

        buff = new (std::nothrow) unsigned char[imagesize];
        if (buff == NULL) return false;
        memset(buff, imagesize, 0x00);

        SSL_read(ssl, buff, imagesize);
        printf("%s\n", buff);
        return false;
    }

    SSL_free(ssl);

    CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
    SSL_CTX_free(ctx);

    return 0;
}

// 프로그램 실행: <Ctrl+F5> 또는 [디버그] > [디버깅하지 않고 시작] 메뉴
// 프로그램 디버그: <F5> 키 또는 [디버그] > [디버깅 시작] 메뉴

// 시작을 위한 팁: 
//   1. [솔루션 탐색기] 창을 사용하여 파일을 추가/관리합니다.
//   2. [팀 탐색기] 창을 사용하여 소스 제어에 연결합니다.
//   3. [출력] 창을 사용하여 빌드 출력 및 기타 메시지를 확인합니다.
//   4. [오류 목록] 창을 사용하여 오류를 봅니다.
//   5. [프로젝트] > [새 항목 추가]로 이동하여 새 코드 파일을 만들거나, [프로젝트] > [기존 항목 추가]로 이동하여 기존 코드 파일을 프로젝트에 추가합니다.
//   6. 나중에 이 프로젝트를 다시 열려면 [파일] > [열기] > [프로젝트]로 이동하고 .sln 파일을 선택합니다.
