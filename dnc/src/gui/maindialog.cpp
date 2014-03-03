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

#include <QLabel>
#include <QDebug>

#include "maindialog.h"
#include "accountsettings.h"
#include "logsettings.h"
#include "generalsettings.h"
#include "wizarddialog.h"

#include <logger.h>

#include "../config.h"
#include "../dnc.h"

struct dnc_cfg *dnc_cfg;

/* Hack to access this from static method */
static void *obj_this;

MainDialog::MainDialog()
{
	/* Check if the client is provisioned */
	/* FIXME check harder */
	QFile file(DNC_IP_FILE);
	if (!file.exists()) {
		this->wizardDialog = new WizardDialog(this);
		this->wizardDialog->show();
	}
	else {
		NowRun();
	}
}

MainDialog::~MainDialog()
{
}

void MainDialog::NowRun()
{
	centerWidget(this);
	this->show();

	obj_this = this;

	ui.setupUi(this);
	QIcon accountIcon(QLatin1String(":rc/user.svg"));
	QListWidgetItem *account = new QListWidgetItem(accountIcon, "Account", ui.labelWidget);
	account->setSizeHint(QSize(0, 32));
	this->accountSettings = new AccountSettings(this);
	ui.stack->addWidget(this->accountSettings);

	QIcon syslogIcon(QLatin1String(":rc/loop_alt4.svg"));
	QListWidgetItem *syslog = new QListWidgetItem(syslogIcon, "Log Activity", ui.labelWidget);
	syslog->setSizeHint(QSize(0, 32));
	this->logSettings = new LogSettings;
	ui.stack->addWidget(this->logSettings);

	QIcon generalIcon(QLatin1String(":rc/cog.svg"));
	QListWidgetItem *general = new QListWidgetItem(generalIcon, "General", ui.labelWidget);
	general->setSizeHint(QSize(0, 32));
	this->generalSettings = new GeneralSettings(this);
	ui.stack->addWidget(this->generalSettings);

	ui.labelWidget->setCurrentRow(ui.labelWidget->row(account));

	connect(ui.labelWidget, SIGNAL(currentRowChanged(int)),
		ui.stack, SLOT(setCurrentIndex(int)));

	connect(this->ui.exitButton, SIGNAL(rejected()), qApp, SLOT(quit()));

	createTrayIcon();
	setTrayIcon();
	trayIcon->show();	
	
	dnc_cfg = (struct dnc_cfg*)calloc(1, sizeof(struct dnc_cfg));
	dnc_cfg->ev.on_log = this->onLog;

	if (dnc_config_init(dnc_cfg)) {
		jlog(L_ERROR, "dnc]> dnc_config_init failed :: %s:%i", __FILE__, __LINE__);
		return;
	}

	if (dnc_cfg->auto_connect != 0) {
		emit this->generalSettings->slotCheckAutoConnect();
		emit accountSettings->slotConnWaiting();
		emit this->slotFireConnection();
	}
}

void MainDialog::slotWizardCancel()
{
	QApplication::quit();
}

void MainDialog::slotWizardNext()
{
	this->ProvKey = this->wizardDialog->ProvKey;
	delete this->wizardDialog;
	this->NowRun();

	dnc_config_toggle_auto_connect(0);

	emit accountSettings->slotConnWaiting();
	emit this->slotFireConnection();
}
void MainDialog::slotToggleAutoConnect(int checked)
{
	dnc_config_toggle_auto_connect(checked);
}

void MainDialog::slotFireConnection(void)
{
	if (this->ProvKey.length() == 36) {
		const char *str = this->ProvKey.toStdString().c_str();
		dnc_cfg->prov_code = strdup(str);
	}

	dnc_cfg->ev.on_connect = this->onConnect;
	dnc_cfg->ev.on_disconnect = this->onDisconnect;

	jlog(L_NOTICE, "dnc]> connecting...");
	dnc_init_async(dnc_cfg);
}

void MainDialog::slotResetAccount()
{
	QMessageBox::StandardButton reply;
	reply = QMessageBox::warning(this, "DynVPN Client", "Exit now, and manually restart DynVPN.",
					QMessageBox::Yes|QMessageBox::No);

	if (reply == QMessageBox::Yes) {
		QFile file(DNC_IP_FILE);
		file.remove();
		qApp->quit();
	}
}

void MainDialog::onLog(const char *logline)
{
	MainDialog *_this = static_cast<MainDialog*>(obj_this);	
	QMetaObject::invokeMethod(_this->logSettings, "slotUpdateLog",
	Qt::QueuedConnection, Q_ARG(QString, QString::fromStdString(logline)));
}

void MainDialog::onConnect(const char *ip)
{
	MainDialog *_this = static_cast<MainDialog*>(obj_this);	
	QMetaObject::invokeMethod(_this->accountSettings, "slotOnConnect",
	Qt::QueuedConnection, Q_ARG(QString, QString::fromStdString(ip)));
}

void MainDialog::onDisconnect()
{
	MainDialog *_this = static_cast<MainDialog*>(obj_this);	
	QMetaObject::invokeMethod(_this->accountSettings, "slotConnWaiting",
	Qt::QueuedConnection);
}

void MainDialog::createTrayIcon()
{
	trayIcon = new QSystemTrayIcon(this);

	connect(trayIcon,
		SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
		this,
		SLOT(trayIconClicked(QSystemTrayIcon::ActivationReason))
	);
}

void MainDialog::setTrayIcon()
{
	trayIcon->setIcon(QIcon(":rc/share.svg"));
}

void MainDialog::trayIconClicked(QSystemTrayIcon::ActivationReason reason)
{
	if (this->isVisible())
		this->hide();
	else {
		centerWidget(this);
		this->show();
	}
}

void MainDialog::closeEvent(QCloseEvent *event)
{
	QMessageBox::StandardButton reply;
	reply = QMessageBox::warning(this, "DynVPN Client", "Are you sure you want to quit ?",
					QMessageBox::Yes|QMessageBox::No);

	if (reply == QMessageBox::No) {
		event->ignore();
	} else if (trayIcon->isVisible()) {
		trayIcon->setVisible(false);
	}
}

void MainDialog::centerWidget(QWidget *w)
{
	if (w->isFullScreen())
		return;

	QSize size;
	size = w->size();

	QDesktopWidget *d = QApplication::desktop();
	int ws = d->width();
	int h = d->height();
	int mw = size.width();
	int mh = size.height();
	int cw = (ws/2) - (mw/2);
	int ch = (h/2) - (mh/2);
	w->move(cw,ch);
}

