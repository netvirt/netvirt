#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <QJsonDocument>
#include <QNetworkRequest>
#include <QNetworkAccessManager>
#include <QUrl>

#include "agent.h"
#include "logging.h"
#include "native.h"

NetvirtAgent::NetvirtAgent()
    : _config(new Config())
{
}

NetvirtAgent::~NetvirtAgent() {
    delete this->_config;
}

void NetvirtAgent::initialize() {
    if (this->_config->isProvisioned()) {
        log_info("NetvirtAgent is provisioned");
        emit provisioned();
    }
}

void NetvirtAgent::provision(const QString &provisioning_key) {
    QByteArray csr, private_key;
    qDebug() << "Generating CSR...";
    this->gen_X509Req(csr, private_key);

    QUrl url;
    url.setScheme("http");
    url.setHost(this->_config->controllerHost());
    url.setPort(this->_config->controllerPort());
    url.setPath("/1.0/provisioning");

    QNetworkRequest request = QNetworkRequest(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Accept", "application/json");

    QVariantMap body;
    body["provisioning_key"] = provisioning_key;
    body["csr"] = csr;
    body["client_version"] = "0.6";
    QByteArray raw_body = QJsonDocument::fromVariant(body).toJson();

    qDebug() << "Sending provisioning request to" << url.toString();
    qDebug() << "With body" << raw_body;

    QNetworkAccessManager *http = new QNetworkAccessManager(this);
    this->_provisioning_reply = http->post(request, raw_body);
    connect(this->_provisioning_reply, SIGNAL(finished()),
            this, SLOT(provisioningFinished()));
    connect(this->_provisioning_reply, SIGNAL(error(QNetworkReply::NetworkError)),
            this, SLOT(provisioningError(QNetworkReply::NetworkError)));
}

void NetvirtAgent::provisioningFinished()
{
    qDebug() << Q_FUNC_INFO;

    this->_config->provision();

    emit provisioned();
}

void NetvirtAgent::provisioningError(QNetworkReply::NetworkError error)
{
    qDebug() << Q_FUNC_INFO;
    qDebug() << error;
}

void NetvirtAgent::connect_(const QString &host, const QString &port, const QString &secret) {
    start_service(host, port, secret);
    emit connected();
}

void NetvirtAgent::disconnect_() {
    emit disconnected();
}


bool NetvirtAgent::gen_X509Req(QByteArray &result, QByteArray &private_key_text)
{
    int good_so_far = 0;
    RSA *rsa = NULL;
    BIGNUM *big_number = NULL;

    int version = 1;
    int bits = 2048;
    unsigned long factor = RSA_F4;

    X509_REQ *csr = NULL;
    X509_NAME *x509_name = NULL;
    EVP_PKEY *key_pair = NULL;

    BIO *bio_csr = NULL;
    long csr_size = 0;
    char *csr_ptr = NULL;

    BIO *bio_private_key = NULL;
    long private_key_size = 0;
    char *private_key_ptr = NULL;

    const char *country = "CA";
    const char *province = "BC";
    const char *city = "Vancouver";
    const char *organization = "Netvirt";
    const char *common_name = "localhost";

    // 1. generate rsa key
    big_number = BN_new();
    good_so_far = BN_set_word(big_number,factor);
    if(good_so_far != 1){
        goto free_all;
    }

    rsa = RSA_new();
    good_so_far = RSA_generate_key_ex(rsa, bits, big_number, NULL);
    if(good_so_far != 1){
        goto free_all;
    }

    // 2. set version of x509 req
    csr = X509_REQ_new();
    good_so_far = X509_REQ_set_version(csr, version);
    if (good_so_far != 1){
        goto free_all;
    }

    // 3. set subject of x509 req
    x509_name = X509_REQ_get_subject_name(csr);

    good_so_far = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)country, -1, -1, 0);
    if (good_so_far != 1){
        goto free_all;
    }

    good_so_far = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)province, -1, -1, 0);
    if (good_so_far != 1){
        goto free_all;
    }

    good_so_far = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)city, -1, -1, 0);
    if (good_so_far != 1){
        goto free_all;
    }

    good_so_far = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)organization, -1, -1, 0);
    if (good_so_far != 1){
        goto free_all;
    }

    good_so_far = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)common_name, -1, -1, 0);
    if (good_so_far != 1){
        goto free_all;
    }

    // 4. set public key of x509 req
    key_pair = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key_pair, rsa);
    rsa = NULL;   // will be free rsa when EVP_PKEY_free(key_pair)

    good_so_far = X509_REQ_set_pubkey(csr, key_pair);
    if (good_so_far != 1){
        goto free_all;
    }

    // 5. set sign key of x509 req
    good_so_far = X509_REQ_sign(csr, key_pair, EVP_sha1());    // good_so_farurn csr->signature->length
    if (good_so_far <= 0){
        goto free_all;
    }

    bio_csr = BIO_new(BIO_s_mem());
    good_so_far = PEM_write_bio_X509_REQ(bio_csr, csr);
    csr_size = BIO_get_mem_data(bio_csr, &csr_ptr);
    *(csr_ptr + csr_size) = '\0';
    result = QByteArray(csr_ptr, csr_size+1);

    bio_private_key = BIO_new(BIO_s_mem());
    good_so_far = PEM_write_bio_PrivateKey(bio_private_key, key_pair, NULL, NULL, 0, 0, NULL);
    private_key_size = BIO_get_mem_data(bio_private_key, &private_key_ptr);
    *(private_key_ptr + private_key_size) = '\0';
    private_key_text = QByteArray(private_key_ptr, private_key_size+1);

    // 6. free
free_all:
    X509_REQ_free(csr);
    BIO_free_all(bio_csr);

    EVP_PKEY_free(key_pair);
    BN_free(big_number);

    return (good_so_far == 1);
}
