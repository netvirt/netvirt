/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2016
 * Nicolas J. Bouliane <admin@netvirt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QProcessEnvironment>
#include <stdio.h>

#include "agent.h"

int main(int argc, char *argv[])
{
    // The config file will be rewritten when provisioning is completed. But we
    // don't want the config file coming from the tests to be modified, so we
    // make a copy and modify it.
    char source[] = "/tmp/netvirt-config/init.ini";
    char destination_dir[] = "/root/.config/netvirt";
    char destination[] = "/root/.config/netvirt/config.ini";
    printf("Copying %s to %s...\n", source, destination);
    QDir::root().mkpath(destination_dir);
    QFile::copy(source, destination);

    printf("Netvirt-client for tests starting...\n");
    QCoreApplication app(argc, argv);
    NetvirtAgent agent;
    QObject::connect(&agent, SIGNAL(provisioned()), &app, SLOT(quit()));
    qDebug() << QProcessEnvironment::systemEnvironment().keys();
    QString provisioning_key = QProcessEnvironment::systemEnvironment().value("provisioning_key");
    agent.provision(provisioning_key);
    return app.exec();
}
