/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2013
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <QApplication>
#include <QLineEdit>
#include <QPushButton>
#include <QFont>

#include "MyWindow.h"

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);
	MyWindow w;

	w.resize(500, 150);

	QPushButton connect("Connect", &w);

	w.provCode = new QLineEdit("", &w);
	w.provCode->move(0,60);
	w.provCode->resize(300, 30);

	QObject::connect(&connect, SIGNAL(clicked()), &w, SLOT(connect()));

	w.show();
	return app.exec();
}
