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

#include <QFile>

#include <stdio.h>
#include "MyWindow.h"

#include <logger.h>
#include "../config.h"
#include "../dnc.h"

struct dnc_cfg *dnc_cfg;

MyWindow::MyWindow(QMainWindow *parent, Qt::WFlags flags)
    : QMainWindow(parent, flags)
{
	ui.setupUi(this);

	createTrayIcon();
	setIcon();

	trayIcon->show();

	QFile file(DNC_IP_FILE);

	if (file.exists()) {
		this->ui.connection_label->setText("Not connected");
		this->ui.info_label->setText("");
		this->ui.prov_key_checkBox->setCheckState(Qt::Unchecked);
	}

	connect(this->ui.exit_button, SIGNAL(clicked()), qApp, SLOT(quit()));

	dnc_cfg = (struct dnc_cfg*)calloc(1, sizeof(struct dnc_cfg));

	if (dnc_config_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_config_init failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (dnc_cfg->auto_connect != 0) {
		this->ui.autoconn_checkBox->setCheckState(Qt::Checked);
		if (file.exists()) {
			MyWindow::on_connect_button_clicked();
		}
	}
}

MyWindow::~MyWindow()
{
	delete trayIcon;
}

void MyWindow::on_autoconn_checkBox_stateChanged(int checked)
{
	dnc_config_toggle_auto_connect(checked);
}

void MyWindow::on_prov_key_checkBox_stateChanged(int checked)
{
	this->ui.provisioning_key_input->setEnabled(checked == Qt::Checked);
}

void MyWindow::on_connect_button_clicked()
{

	QString provisioning_key = this->ui.provisioning_key_input->text();

	if (! provisioning_key.isEmpty()) {
		const char *str = provisioning_key.toStdString().c_str();
		dnc_cfg->prov_code = strdup(str);
	}

	dnc_cfg->ev.on_connect = this->on_connect;
	dnc_cfg->ev.obj = (void *)this;

	jlog(L_NOTICE, "dnc]> connecting...");

	if (dnc_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_init() failed :: %s:%i", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	this->ui.info_label->setText("");
	this->ui.prov_key_checkBox->setCheckState(Qt::Unchecked);
	this->ui.connect_button->setEnabled(false);
}

void MyWindow::on_connect(void *obj, const char *ip)
{
	QString info_ip = QString("Your IP:%1").arg(QString::fromUtf8(ip));

	MyWindow *_this = static_cast<MyWindow*>(obj);

	_this->ui.connection_label->setText("Now connected !");
	_this->ui.info_label->setText(info_ip);
}

void MyWindow::createTrayIcon()
{
	trayIcon = new QSystemTrayIcon(this);

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
	if (this->isVisible())
		this->hide();
	else
		this->show();
}

void MyWindow::closeEvent(QCloseEvent *event)
{
	QMessageBox::StandardButton reply;
	reply = QMessageBox::warning(this, "DynVPN Client", "Are you sure you want to quit ?",
					QMessageBox::Yes|QMessageBox::No);

	if (reply == QMessageBox::No) {
		event->ignore();
	} else {

		if (trayIcon->isVisible()) {
			trayIcon->setVisible(false);
		}
	}
}

