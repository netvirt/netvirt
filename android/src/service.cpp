#include <QTimer>
#include <QUdpSocket>

#include "logging.h"
#include "service.h"

VPNService::VPNService(const QString& server_host_,
                       int server_port_,
                       const QString& secret_)
{
    this->server_host = QHostAddress(server_host_);
    this->server_port = server_port_;
    this->secret = secret_;
}

void VPNService::testSlot() {
    log_info("test");
}

void VPNService::initialize() {
    log_info("Initializing VPNService...");

    this->server = new QUdpSocket(this);

    connect(this, SIGNAL(testSignal()),
            this, SLOT(testSlot()));
    emit testSignal();
    QTimer::singleShot(400, this, SLOT(testSlot()));
}
