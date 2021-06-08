#include <iostream>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "NetworkTCP.h"

#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

static std::vector<unsigned char> sendbuff;
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

std::string getOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();        /* load & register all cryptos, etc. */
    SSL_load_error_strings();            /* load all error messages */
    method = SSLv23_server_method();        /* create new server-method instance */
    ctx = SSL_CTX_new(method);            /* create new context from method */
    if (ctx == NULL)
    {
        printf("ctx error\n");
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void VerifyCertificate(SSL_CTX* ctx) {
    X509_STORE *store;
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(root_ca, -1);

    PEM_read_bio_X509(bio, &cert, 0, NULL);
    if (cert == NULL) {
        printf("PEM_read_bio_X509 failed...\n");
    }

    /* get a pointer to the X509 certificate store (which may be empty!) */
    store = SSL_CTX_get_cert_store((SSL_CTX *)ctx);

    /* add our certificate to this store */
    if (X509_STORE_add_cert(store, cert) == 0) {
        printf("error adding certificate\n");
    }

    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, cert, NULL);
    int res = X509_verify_cert(store_ctx);

    printf("Verify result : %d\n", res);
}


int main(int argc, char *argv[])
{
    std::cout << "Hello code" << std::endl;

    while (1)
    {
        TTcpListenPort *TcpListenPort;
        TTcpConnectedPort *TcpConnectedPort;
        struct sockaddr_in cli_addr;
        socklen_t clilen;

        // SSL Context 관련 구조체 선언
        SSL_CTX *ctx = InitServerCTX();
        LoadCertificates(ctx, "../../Certificates/server.pem", "../../Certificates/server.key");

        //  Listen
        if ((TcpListenPort = OpenTcpListenPort(5555)) == NULL)
        {
            printf("OpenTcpListenPortFiled\n");
            return (-1);
        }

        clilen = sizeof(cli_addr);
        printf("Listening for connections\n");
        if ((TcpConnectedPort = AcceptTcpConnection(TcpListenPort, &cli_addr, &clilen)) == NULL)
        {
            printf("AcceptTcpConnection Failed\n");
            return (-1);
        }
        printf("Connection from %1x, port %x\n", cli_addr.sin_addr.s_addr, cli_addr.sin_port);

        /* TCP connection is ready. Do server side SSL. */
        SSL *ssl = SSL_new(ctx); // 설정된 Context를 이용하여 SSL 세션의 초기화 작업을 수행한다.
        CHK_NULL(ssl);
        SSL_set_fd(ssl, TcpConnectedPort->ConnectedFd);
        int err = SSL_accept(ssl);    // SSL 세션을 통해 클라이언트의 접속을 대기한다.
        if((err) == -1) {
            printf("SSL_accept Failed\n");
            printf("%s", getOpenSSLError().c_str());
            exit(2);
        }

        /* Get the cipher – opt */
        printf("SSL connection using %s\n", SSL_get_cipher(ssl));

        //  TODO: client 인증서를 받음
        X509 *client_cert = SSL_get_peer_certificate(ssl);
        if(client_cert != NULL) {
            printf("Client certificate:\n");

            char* str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
            CHK_NULL(str);
            printf("\t subject: %s\n", str);
            OPENSSL_free(str);

            str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
            CHK_NULL(str);
            printf("\t issuer: %s\n", str);
            OPENSSL_free(str);

            VerifyCertificate(ctx);
            /* We could do all sorts of certificate verification stuff here before deallocating the certificate. */
            X509_free(client_cert);
        } else {
            printf("Client does not have certificate.\n");
        }


        std::string msg_to_send = "Hello There~!!!";
        unsigned int data_size = msg_to_send.length() + 1;
        std::cout << "SENDING : " << msg_to_send << std::endl;

        if (!ssl)
        {
            printf("Accepted connection Request on socket\n");
            if (WriteDataTcp(TcpConnectedPort, (unsigned char *)&data_size, sizeof(data_size)) != sizeof(data_size))
            {
                printf("Mismatch write data\n");
                return (-1);
            }
            WriteDataTcp(TcpConnectedPort, (unsigned char *)msg_to_send.c_str(), data_size);

            printf("Data sent and closing\n");
            CloseTcpConnectedPort(&TcpConnectedPort);
        } else {
            printf("Accepted connection Request on SSL\n");
            err = SSL_write(ssl, (unsigned char *)&data_size, sizeof(data_size));
            if ((err) == -1) {
                printf("SSL_write Failed 1\n");
                exit(2);
            }
            err = SSL_write(ssl, (unsigned char *)msg_to_send.c_str(), data_size);
            if((err) == -1) {
                printf("SSL_write Failed 2\n");
                exit(2);
            }

            printf("Data sent and closing\n");
            close(TcpConnectedPort->ConnectedFd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }


    }

    return 0;
}