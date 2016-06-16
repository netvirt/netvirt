#include <QTimer>
#include <QSocketNotifier>
#include <QUdpSocket>

#include "logging.h"
#include "native.h"
#include "service.h"

const int MAX_CLIENT_READ = 32767;
const int MAX_SERVER_READ = 32767;
const int SERVER_PING_INTERVAL_MS = 15000;

VPNService::VPNService(const QString& server_host_,
                       int server_port_,
                       const QString& secret_)
    : client(new QFile("")),
      ping_timer(new QTimer(this))
{
    this->server_host = server_host_;
    this->server_port = server_port_;
    this->secret = secret_;
    connect(this->ping_timer, SIGNAL(timeout()),
            this, SLOT(pingServer()));
    this->ping_timer->start(SERVER_PING_INTERVAL_MS);
}

void VPNService::testSlot() {
    log_info("test");
}

void VPNService::initialize() {
    log_info("Initializing VPNService... to " + this->server_host + ":" + QString::number(this->server_port));

    this->server = new QUdpSocket(this);
    connect(this->server, SIGNAL(connected()),
            this, SLOT(handshake()));
    this->server->connectToHost(this->server_host, this->server_port);
}

void VPNService::handshake() {
    log_info("Sending handshake...");
    protect(this->server->socketDescriptor());
    QByteArray datagram;
    datagram.append('\0');
    datagram.append(secret);
    connect(this->server, SIGNAL(readyRead()),
            this, SLOT(handshakeReceived()));
    this->server->write(datagram);
}

void VPNService::handshakeReceived() {
    log_info("Handshake received!");
    disconnect(this->server, SIGNAL(readyRead()),
               this, SLOT(handshakeReceived()));

    QByteArray datagram = this->server->read(this->server->pendingDatagramSize());
    datagram = datagram.right(datagram.size() - 1);
    int client_descriptor = this->configureInterface(QString::fromUtf8(datagram));
    this->client->open(client_descriptor,
                       QIODevice::ReadWrite | QIODevice::Unbuffered,
                       QFileDevice::AutoCloseHandle);

    QSocketNotifier *client_to_server_notifier = new QSocketNotifier(client_descriptor,
                                                                     QSocketNotifier::Read,
                                                                     this);
    connect(client_to_server_notifier, SIGNAL(activated(int)),
            this, SLOT(clientToServer()));
    connect(this->server, SIGNAL(readyRead()),
            this, SLOT(serverToClient()));
    this->server->readAll();
    this->client->readAll();
}

void VPNService::clientToServer() {
    log_info("Start receiving from client");
    QByteArray packet = this->client->read(MAX_CLIENT_READ);
    while(!packet.isEmpty()) {
        log_info("Received packet from client");
        this->server->write(packet);
        packet = this->client->read(MAX_CLIENT_READ);
    }
    log_info("End receiving from client");
}

void VPNService::serverToClient() {
    log_info("Start receiving from server");
    while(this->server->hasPendingDatagrams()) {
        log_info("Received packet from server");
        QByteArray packet = this->server->read(this->server->pendingDatagramSize());
        this->client->write(packet);
    }
    log_info("End receiving from server");
}

void VPNService::pingServer() {
    log_info("Pinging server");
    QByteArray packet;
    packet.append('\0');
    this->server->write(packet);
}

int VPNService::configureInterface(const QString &parameters) {
    log_info("Configuring interface...");
    int mtu = 1500, address_mask = 24, route_mask = 24;
    QString address, route, dns_server, search_domain;

    foreach(const QString &parameter, parameters.split(" ")) {
        QStringList fields = parameter.split(",");
        switch (fields.at(0).at(0).toLatin1()) {
        case 'm':
            mtu = fields.at(1).toInt();
            log_info("Received MTU " + QString::number(mtu).toUtf8());
            break;
        case 'a':
            address = fields.at(1);
            address_mask = fields.at(2).toInt();
            log_info("Received address " + address.toUtf8() + "/" + QString::number(address_mask).toUtf8());
            break;
        case 'r':
            route = fields.at(1);
            route_mask = fields.at(2).toInt();
            log_info("Received route " + route.toUtf8() + "/" + QString::number(route_mask).toUtf8());
            break;
        case 'd':
            dns_server = fields.at(1);
            log_info("Received DNS server " + dns_server.toUtf8());
            break;
        case 's':
            search_domain = fields.at(1);
            log_info("Received search domain " + search_domain.toUtf8());
            break;
        }
    }
    int client_descriptor = configure(mtu,
                                      address,
                                      address_mask,
                                      route,
                                      route_mask,
                                      dns_server,
                                      search_domain,
                                      this->server_host);
    log_info("Created interface " + QString::number(client_descriptor).toUtf8());
    return client_descriptor;
}
