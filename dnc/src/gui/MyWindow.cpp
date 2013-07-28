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

MyWindow::MyWindow(QMainWindow *parent, Qt::WFlags flags)
    : QMainWindow(parent, flags)
{
	ui.setupUi(this);

	createActions();
	createTrayIcon();
	setIcon();

	trayIcon->show();
}

MyWindow::~MyWindow()
{
	delete trayIcon;
	delete trayIconMenu;
	delete open;
	delete close;
}

void MyWindow::on_connect_button_clicked()
{
	struct dnc_cfg *dnc_cfg = (struct dnc_cfg*)calloc(1, sizeof(struct dnc_cfg));

	QString provisioning_code = this->ui.provisioning_code_input->text();

	if (! provisioning_code.isEmpty()) {
		const char *str = provisioning_code.toStdString().c_str();
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

void MyWindow::createActions()
{
	open = new QAction(tr("&Open"), this);
	connect(open, SIGNAL(triggered()), this, SLOT(show()));

	close = new QAction(tr("&Quit"), this);
	connect(close, SIGNAL(triggered()), qApp, SLOT(quit()));
}

void MyWindow::createTrayIcon()
{
	trayIconMenu = new QMenu(this);

	trayIconMenu->addAction(open);
	trayIconMenu->addSeparator();
	trayIconMenu->addAction(close);

	trayIcon = new QSystemTrayIcon(this);
	trayIcon->setContextMenu(trayIconMenu);

	connect(trayIcon,
		SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
		this,
		SLOT(trayIconClicked(QSystemTrayIcon::ActivationReason))
	);
}

void MyWindow::setIcon()
{
	trayIcon->setIcon(QIcon(":dnc.ico"));
}

void MyWindow::trayIconClicked(QSystemTrayIcon::ActivationReason reason)
{
	if (reason == QSystemTrayIcon::Trigger)
		this->show();
}

void MyWindow::closeEvent(QCloseEvent *event)
{
	if (trayIcon->isVisible()) {
		trayIcon->showMessage(tr("Still here !"),
		tr("This application is still running. To quit please click this icon and select Quit"));
		hide();

		event->ignore();
	}
}
