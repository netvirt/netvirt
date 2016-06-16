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

#include "agent.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    NetvirtAgent agent;
    agent.connect_("server", "8000", "test");
    return app.exec();
}
