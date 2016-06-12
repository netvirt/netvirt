#include <QThread>

#include "service.h"
#include "service_main.h"

MainThread::MainThread(const QString &server_host,
                       int server_port,
                       const QString &secret)
    : server_host(server_host),
      server_port(server_port),
      secret(secret)
{
}

void MainThread::run() {
    VPNService *service = new VPNService(this->server_host,
                                         this->server_port,
                                         this->secret);
    service->initialize();
    QThread::run();
}
