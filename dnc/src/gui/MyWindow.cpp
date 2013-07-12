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

#include <stdio.h>
#include "MyWindow.h"

#include <logger.h>
#include "../config.h"
#include "../dnc.h"

MyWindow::MyWindow(QMainWindow *parent, Qt::WFlags fl) : QMainWindow(parent, fl)
{
	provCode = new QLineEdit;
	provCode->setFocus();
}

MyWindow::~MyWindow()
{
}

void MyWindow::connect()
{
	struct dnc_cfg *dnc_cfg;
	dnc_cfg = (struct dnc_cfg*)calloc(1, sizeof(struct dnc_cfg));

	const char *str = NULL;
	QString qt_str;

	if (provCode->text().length() > 0) {
		qt_str = provCode->text();
		str = qt_str.toStdString().c_str();

		dnc_cfg->prov_code = strdup(str);
	}

	if (dnc_config_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_config_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	jlog(L_NOTICE, "dnc]> connecting...");

	if (dnc_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	}
