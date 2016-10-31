#include <QDebug>
#include <QStandardPaths>

#include "config.h"
#include "logging.h"


Config::Config() {
    QString path = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + "/netvirt/config.ini";
    qDebug() << "Reading config from" << path << "...";
    this->_settings = new QSettings(path, QSettings::IniFormat);
    if (this->_settings->allKeys().isEmpty()) {
        qDebug() << "Config file does not exist.";
    }
}

QString Config::controllerHost() {
    return this->_settings->value("controller_host", "dynvpn.com").toString();
}

int Config::controllerPort() {
    return this->_settings->value("controller_port", 8001).toInt();
}

void Config::provision() {
    this->_settings->setValue("provisioned", true);
    this->_settings->sync();
}

bool Config::isProvisioned() {
    return this->_settings->value("provisioned", false).toBool();
}
