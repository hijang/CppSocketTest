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

static const char* root_ca = "-----BEGIN CERTIFICATE-----\n"
                            "MIICODCCAd8CFGnngwBSCkZRYpt92Eo8R4SyB1h8MAoGCCqGSM49BAMCMIGdMQsw\n"
                            "CQYDVQQGEwJLUjEOMAwGA1UECAwFU2VvdWwxEDAOBgNVBAcMB0dhbmduYW0xDDAK\n"
                            "BgNVBAoMA0xHRTEWMBQGA1UECwwNU2VjU3BlY2lhbGlzdDElMCMGA1UEAwwcNHRl\n"
                            "bnRpYWwgQ0EgUm9vdCBDZXJ0aWZpY2F0ZTEfMB0GCSqGSIb3DQEJARYQdGVobG9v\n"
                            "QGdtYWlsLmNvbTAgFw0yMTA2MDUxNzEwNThaGA80NzU5MDUwMjE3MTA1OFowgZ0x\n"
                            "CzAJBgNVBAYTAktSMQ4wDAYDVQQIDAVTZW91bDEQMA4GA1UEBwwHR2FuZ25hbTEM\n"
                            "MAoGA1UECgwDTEdFMRYwFAYDVQQLDA1TZWNTcGVjaWFsaXN0MSUwIwYDVQQDDBw0\n"
                            "dGVudGlhbCBDQSBSb290IENlcnRpZmljYXRlMR8wHQYJKoZIhvcNAQkBFhB0ZWhs\n"
                            "b29AZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4O7qjNWPVgUF\n"
                            "5CPbbe24bAGyV+AKKrrtbQ/eaYn90kpmtkL7o5br7GsZISW2SBbmBmYRH4Igg3/Y\n"
                            "ftf4j0BCTDAKBggqhkjOPQQDAgNHADBEAiByX2OOGwkPgJm0hFm/Z5UjTvkLbPUK\n"
                            "txYcyeSWQB/hzAIgez3HVhXUOKoAat9/hS86IG/bdubhggy4wOujM2ebfXM=\n"
                            "-----END CERTIFICATE-----";

static const char* asr_ca = "-----BEGIN CERTIFICATE-----\n"
                            "MIIGGTCCBAGgAwIBAgIQE31TnKp8MamkM3AZaIR6jTANBgkqhkiG9w0BAQwFADCB\n"
                            "iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl\n"
                            "cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV\n"
                            "BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTgx\n"
                            "MTAyMDAwMDAwWhcNMzAxMjMxMjM1OTU5WjCBlTELMAkGA1UEBhMCR0IxGzAZBgNV\n"
                            "BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE\n"
                            "ChMPU2VjdGlnbyBMaW1pdGVkMT0wOwYDVQQDEzRTZWN0aWdvIFJTQSBPcmdhbml6\n"
                            "YXRpb24gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0B\n"
                            "AQEFAAOCAQ8AMIIBCgKCAQEAnJMCRkVKUkiS/FeN+S3qU76zLNXYqKXsW2kDwB0Q\n"
                            "9lkz3v4HSKjojHpnSvH1jcM3ZtAykffEnQRgxLVK4oOLp64m1F06XvjRFnG7ir1x\n"
                            "on3IzqJgJLBSoDpFUd54k2xiYPHkVpy3O/c8Vdjf1XoxfDV/ElFw4Sy+BKzL+k/h\n"
                            "fGVqwECn2XylY4QZ4ffK76q06Fha2ZnjJt+OErK43DOyNtoUHZZYQkBuCyKFHFEi\n"
                            "rsTIBkVtkuZntxkj5Ng2a4XQf8dS48+wdQHgibSov4o2TqPgbOuEQc6lL0giE5dQ\n"
                            "YkUeCaXMn2xXcEAG2yDoG9bzk4unMp63RBUJ16/9fAEc2wIDAQABo4IBbjCCAWow\n"
                            "HwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBfZ1iUn\n"
                            "Z/kxwklD2TA2RIxsqU/rMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/\n"
                            "AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAbBgNVHSAEFDASMAYG\n"
                            "BFUdIAAwCAYGZ4EMAQICMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNl\n"
                            "cnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNy\n"
                            "bDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQudXNlcnRy\n"
                            "dXN0LmNvbS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEFBQcwAYYZ\n"
                            "aHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAThNA\n"
                            "lsnD5m5bwOO69Bfhrgkfyb/LDCUW8nNTs3Yat6tIBtbNAHwgRUNFbBZaGxNh10m6\n"
                            "pAKkrOjOzi3JKnSj3N6uq9BoNviRrzwB93fVC8+Xq+uH5xWo+jBaYXEgscBDxLmP\n"
                            "bYox6xU2JPti1Qucj+lmveZhUZeTth2HvbC1bP6mESkGYTQxMD0gJ3NR0N6Fg9N3\n"
                            "OSBGltqnxloWJ4Wyz04PToxcvr44APhL+XJ71PJ616IphdAEutNCLFGIUi7RPSRn\n"
                            "R+xVzBv0yjTqJsHe3cQhifa6ezIejpZehEU4z4CqN2mLYBd0FUiRnG3wTqN3yhsc\n"
                            "SPr5z0noX0+FCuKPkBurcEya67emP7SsXaRfz+bYipaQ908mgWB2XQ8kd5GzKjGf\n"
                            "FlqyXYwcKapInI5v03hAcNt37N3j0VcFcC3mSZiIBYRiBXBWdoY5TtMibx3+bfEO\n"
                            "s2LEPMvAhblhHrrhFYBZlAyuBbuMf1a+HNJav5fyakywxnB2sJCNwQs2uRHY1ihc\n"
                            "6k/+JLcYCpsM0MF8XPtpvcyiTcaQvKZN8rG61ppnW5YCUtCC+cQKXA0o4D/I+pWV\n"
                            "idWkvklsQLI+qGu41SWyxP7x09fn1txDAXYw+zuLXfdKiXyaNb78yvBXAfCNP6CH\n"
                            "MntHWpdLgtJmwsQt6j8k9Kf5qLnjatkYYaA7jBU=\n"
                            "-----END CERTIFICATE-----\n";

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


int VerifyCertificate(SSL_CTX* ctx) {
    X509_STORE* store;
    X509* cert = NULL;
    BIO* bio = BIO_new_mem_buf(root_ca, -1);

    PEM_read_bio_X509(bio, &cert, 0, NULL);
    if (cert == NULL) {
        printf("PEM_read_bio_X509 failed...\n");
    }

    /* get a pointer to the X509 certificate store (which may be empty!) */
    store = SSL_CTX_get_cert_store((SSL_CTX*)ctx);

    /* add our certificate to this store */
    if (X509_STORE_add_cert(store, cert) == 0) {
        printf("error adding certificate\n");
    }

    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, cert, NULL);
    return X509_verify_cert(store_ctx);;
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

    X509* server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert != NULL) {
        printf("Client certificate:\n");

        char* str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
        CHK_NULL(str);
        printf("\t subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
        CHK_NULL(str);
        printf("\t issuer: %s\n", str);
        OPENSSL_free(str);

        /* We could do all sorts of certificate verification stuff here before deallocating the certificate. */
        X509_free(server_cert);
    }
    else {
        printf("Server does not have certificate.\n");
        return -1;
    }

    int verified = VerifyCertificate(ctx);
    if (verified <= 0) {
        printf("Verify failed (%d)\n", verified);

        SSL_free(ssl);

        CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
        SSL_CTX_free(ctx);
        return -1;
    }

    do {
        if (!ssl)
        {
            unsigned int imagesize;
            unsigned char* buff;	/* receive buffer */

            if (ReadDataTcp(TcpConnectedPort, (unsigned char*)&imagesize, sizeof(imagesize)) != sizeof(imagesize)) return(false);

            //imagesize = ntohl(imagesize); // convert image size to host format

            printf("imagesize??? %d\n", imagesize);
            if (imagesize < 0) break;

            buff = new (std::nothrow) unsigned char[imagesize];
            if (buff == NULL) break;
            memset(buff, imagesize, 0x00);

            ReadDataTcp(TcpConnectedPort, buff, imagesize);

            printf("%s\n", buff);
        }
        else
        {
            unsigned int imagesize;
            unsigned char* buff;	/* receive buffer */

            int success = SSL_read(ssl, &imagesize, sizeof(imagesize));
            if (success <= 0) break;
            printf("success = %d, imagesize??? %d\n", success, imagesize);
            if (imagesize < 0) break;

            printf("Connected~!\n");

            buff = new (std::nothrow) unsigned char[imagesize];
            if (buff == NULL) break;
            memset(buff, imagesize, 0x00);

            success = SSL_read(ssl, buff, imagesize);
			if (success <= 0) break;
            printf("success = %d, %s\n", success, buff);
        }
        
    } while (0);
    

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
