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

	w.show();
	return app.exec();
}
