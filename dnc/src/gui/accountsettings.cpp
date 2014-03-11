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
#include <QMovie>
#include <QPixmap>

#include "accountsettings.h"

AccountSettings::AccountSettings(MainDialog *dialog)
{
	ui.setupUi(this);
	this->ui.LoadLabel->setVisible(false);
	this->ui.IPLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
	this->ui.IPLabel->setVisible(false);
	this->ui.YourIPLabel->setVisible(false);

	connect(ui.connectButton, SIGNAL(clicked()), this, SLOT(slotConnWaiting()));
	connect(ui.connectButton, SIGNAL(clicked()), dialog, SLOT(slotFireConnection()));

	QMovie *movie = new QMovie(":/rc/loader.gif");
	this->ui.LoadLabel->setMovie(movie);
	movie->start();
}

AccountSettings::~AccountSettings()
{
}

void AccountSettings::slotOnConnect(QString ip)
{
	this->ui.connectionInfoLabel->setText("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Now connected</span></p></body></html>");


this->ui.connectionInfoLabel->setText("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Now connected</span></p></body></html>");

	QString ipFormated = QString("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">%1</span></p></body></html>").arg(ip);
	this->ui.IPLabel->setText(ipFormated);
	this->ui.LoadLabel->setVisible(false);

	this->ui.IPLabel->setVisible(true);
	this->ui.YourIPLabel->setVisible(true);

	this->ui.StatusPix->setVisible(true);
	this->ui.StatusPix->setPixmap(QPixmap(":rc/tick_32.png"));
}

void AccountSettings::slotConnWaiting()
{

	this->ui.connectionInfoLabel->setText("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Connecting...</span></p></body></html>");

	this->ui.LoadLabel->setVisible(true);
	this->ui.connectButton->setEnabled(false);

	this->ui.IPLabel->setVisible(false);
	this->ui.YourIPLabel->setVisible(false);

	this->ui.StatusPix->setVisible(false);
}

