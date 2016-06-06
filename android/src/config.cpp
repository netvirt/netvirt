#include <QStandardPaths>

#include "config.h"
#include "logging.h"

Config::Config() {
    QString path = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + "/config.ini";
    this->_settings = new QSettings(path, QSettings::IniFormat);
}

void Config::provision() {
    this->_settings->setValue("provisioned", true);
    this->_settings->sync();
}

bool Config::isProvisioned() {
    return this->_settings->value("provisioned", false).toBool();
}
