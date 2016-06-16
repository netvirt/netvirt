#include <QDebug>
#include <QHostAddress>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "logging.h"
#include "service_main.h"

#ifndef TUN_INTERFACE_NAME
#define TUN_INTERFACE_NAME "tun0"
#endif

void start_service(const QString &host, const QString &port, const QString &secret) {
    MainThread *service_thread = new MainThread(host, port.toInt(), secret);
    service_thread->start();
}

bool protect(int socket) {
    Q_UNUSED(socket)
    return true;
}

int configure(int mtu,
              const QString &address,
              int address_mask,
              const QString &route,
              int route_mask,
              const QString &dns_server,
              const QString &search_domain,
              const QString &server)
{
    Q_UNUSED(mtu);
    Q_UNUSED(address);
    Q_UNUSED(address_mask);
    Q_UNUSED(route);
    Q_UNUSED(route_mask);
    Q_UNUSED(dns_server);
    Q_UNUSED(search_domain);
    Q_UNUSED(server);

    int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, TUN_INTERFACE_NAME, sizeof(ifr.ifr_name));

    if (ioctl(interface, TUNSETIFF, &ifr)) {
        perror("Cannot get TUN interface");
        exit(1);
    }

    log_info("File descriptor: " + QString::number(interface));
    return interface;
}

void log_info(const char *string) {
    qDebug(string);
}

void log_info(const QString &string) {
    log_info(string.toUtf8());
}

void log_info(const QByteArray &string) {
    log_info(string.data());
}
