/*
 * NetVirt - Network Virtualization Platform
 * Copyright (C) 2009-2014
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

	movie = new QMovie(":/rc/loader.gif");
	this->ui.LoadLabel->setMovie(movie);
}

AccountSettings::~AccountSettings()
{
	delete movie;
}

void AccountSettings::slotOnConnect(QString ip)
{
	this->ui.connectionInfoLabel->setText("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Now connected</span></p></body></html>");
	this->ui.connectionInfoLabel->setText("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Now connected</span></p></body></html>");

	QString ipFormated = QString("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">%1</span></p></body></html>").arg(ip);
	this->ui.IPLabel->setText(ipFormated);
	this->ui.LoadLabel->setVisible(false);
	movie->stop();

	this->ui.IPLabel->setVisible(true);
	this->ui.YourIPLabel->setVisible(true);

	this->ui.StatusPix->setVisible(true);
	this->ui.StatusPix->setPixmap(QPixmap(":rc/tick_32.png"));
}

void AccountSettings::slotConnWaiting()
{

	this->ui.connectionInfoLabel->setText("<html><head/><body><p><span style=\" font-size:14pt; font-weight:600;\">Connecting...</span></p></body></html>");

	movie->start();
	this->ui.LoadLabel->setVisible(true);
	this->ui.connectButton->setEnabled(false);

	this->ui.IPLabel->setVisible(false);
	this->ui.YourIPLabel->setVisible(false);

	this->ui.StatusPix->setVisible(false);

}

