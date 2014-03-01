/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <QApplication>
#include <QCleanlooksStyle>

#include "maindialog.h"

int main(int argc, char *argv[])
{
	#if __APPLE__
		/* On Mac OS, the current directory is /, but the
		 * config file is beside the executable.
		 */
		char *executable_path = dirname(argv[0]);
		chdir(executable_path);
	#endif

	QApplication app(argc, argv);
	app.setStyle(new QCleanlooksStyle());

	MainDialog s;

	return app.exec();
}
