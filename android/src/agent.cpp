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
    QByteArray csr;
    qDebug() << "Generating CSR...";
    this->gen_X509Req(csr);

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


bool NetvirtAgent::gen_X509Req(QByteArray &result)
{
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;

    int nVersion = 1;
    int bits = 2048;
    unsigned long e = RSA_F4;

    X509_REQ *x509_req = NULL;
    X509_NAME *x509_name = NULL;
    EVP_PKEY *pKey = NULL;
    RSA *tem = NULL;
    BIO *out = NULL, *bio_err = NULL;

    long csr_size = 0;
    char *csr_ptr = NULL;

    const char *szCountry = "CA";
    const char *szProvince = "BC";
    const char *szCity = "Vancouver";
    const char *szOrganization = "Netvirt";
    const char *szCommon = "localhost";

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    // 2. set version of x509 req
    x509_req = X509_REQ_new();
    ret = X509_REQ_set_version(x509_req, nVersion);
    if (ret != 1){
        goto free_all;
    }

    // 3. set subject of x509 req
    x509_name = X509_REQ_get_subject_name(x509_req);

    ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }

    ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }

    ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }

    ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }

    ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
    if (ret != 1){
        goto free_all;
    }

    // 4. set public key of x509 req
    pKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pKey, r);
    r = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

    ret = X509_REQ_set_pubkey(x509_req, pKey);
    if (ret != 1){
        goto free_all;
    }

    // 5. set sign key of x509 req
    ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());    // return x509_req->signature->length
    if (ret <= 0){
        goto free_all;
    }

    out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_X509_REQ(out, x509_req);

    csr_size = BIO_get_mem_data(out, &csr_ptr);
    *(csr_ptr + csr_size) = '\0';

    result = QByteArray(csr_ptr, csr_size+1);

    // 6. free
free_all:
    X509_REQ_free(x509_req);
    BIO_free_all(out);

    EVP_PKEY_free(pKey);
    BN_free(bne);

    return (ret == 1);
}
