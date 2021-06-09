#include <iostream>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "NetworkTCP.h"

#define CHK_NULL(x)  \
    if ((x) == NULL) \
        exit(1);
#define CHK_ERR(err, s) \
    if ((err) == -1)    \
    {                   \
        perror(s);      \
        exit(1);        \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1)                 \
    {                                \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

static std::vector<unsigned char> sendbuff;
static const char *root_ca = "-----BEGIN CERTIFICATE-----\n"
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

static const char *asr_ca = "-----BEGIN CERTIFICATE-----\n"
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
SSL_CTX *InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();    /* load & register all cryptos, etc. */
    SSL_load_error_strings();        /* load all error messages */
    method = SSLv23_server_method(); /* create new server-method instance */
    ctx = SSL_CTX_new(method);       /* create new context from method */
    if (ctx == NULL)
    {
        printf("ctx error\n");
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
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

int VerifyCertificate(SSL_CTX *ctx)
{
    X509_STORE *store;
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(root_ca, -1);

    PEM_read_bio_X509(bio, &cert, 0, NULL);
    if (cert == NULL)
    {
        printf("PEM_read_bio_X509 failed...\n");
    }

    /* get a pointer to the X509 certificate store (which may be empty!) */
    store = SSL_CTX_get_cert_store((SSL_CTX *)ctx);

    /* add our certificate to this store */
    if (X509_STORE_add_cert(store, cert) == 0)
    {
        printf("error adding certificate\n");
    }

    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, cert, NULL);
    return X509_verify_cert(store_ctx);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    char buf[256];
    X509 *err_cert;
    int err, depth;
    SSL *ssl;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    std::cout << "depth? " << depth << std::endl;

    char* str = X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);

    str = X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);

    if (!preverify_ok)
    {
        printf("verify error:num=%d:%s:depth=%d:%s\n", err,
               X509_verify_cert_error_string(err), depth, buf);
    }

    return preverify_ok;
}

int main(int argc, char *argv[])
{
    std::cout << "Hello code" << std::endl;

    TTcpListenPort *TcpListenPort;
    TTcpConnectedPort *TcpConnectedPort;
    struct sockaddr_in cli_addr;
    socklen_t clilen;

    // SSL Context 관련 구조체 선언
    SSL_CTX *ctx = InitServerCTX();
    LoadCertificates(ctx, "../../Certificates/server.pem", "../../Certificates/server.key");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER| SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_load_verify_locations(ctx, "../../Certificates/rootca.crt", NULL);
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

    int err = SSL_accept(ssl); // SSL 세션을 통해 클라이언트의 접속을 대기한다.
    if ((err) == -1)
    {
        printf("SSL_accept Failed\n");
        printf("%s", getOpenSSLError().c_str());
        exit(2);
    }

    /* Get the cipher – opt */
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL)
    {
        printf("Client certificate:\n");

        char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
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
    else
    {
        printf("Client does not have certificate.\n");
        SSL_free(ssl);

        CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
        SSL_CTX_free(ctx);
        return -1;
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
    }
    else
    {
        printf("Accepted connection Request on SSL\n");
        err = SSL_write(ssl, (unsigned char *)&data_size, sizeof(data_size));
        if ((err) == -1)
        {
            printf("SSL_write Failed 1\n");
            exit(2);
        }
        err = SSL_write(ssl, (unsigned char *)msg_to_send.c_str(), data_size);
        if ((err) == -1)
        {
            printf("SSL_write Failed 2\n");
            exit(2);
        }

        printf("Data sent and closing\n");
        close(TcpConnectedPort->ConnectedFd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    return 0;
}