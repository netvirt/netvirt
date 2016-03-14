#include "agent.h"

const QString &server_host = "192.168.1.90";
const int server_port = 9095;

NetvirtAgent::NetvirtAgent() :
    server(new QUdpSocket(this))
{
    connect(this->server, SIGNAL(readyRead()),
            this, SLOT(processServerData()));
}

void NetvirtAgent::connect_() {
    this->client2server(QByteArray("hello"));
    emit connected();
}

void NetvirtAgent::disconnect_() {
    emit disconnected();
}

void NetvirtAgent::processServerData() {
    while (this->server->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(this->server->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        this->server->readDatagram(datagram.data(), datagram.size(),
                                   &sender, &senderPort);

        server2client(datagram);
    }
}

void NetvirtAgent::server2client(QByteArray payload) {

    QString message = QString(payload);
    message.left(message.size() - 1);
    emit messageReceived(message);
}

void NetvirtAgent::client2server(const QByteArray payload) {
    this->server->writeDatagram(payload,
                                payload.size(),
                                QHostAddress(server_host),
                                server_port);
}
