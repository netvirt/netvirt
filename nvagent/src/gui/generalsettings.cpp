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

#include <QDebug>
#include <QMovie>
#include <QUrl>
#include <QNetworkRequest>
#include "generalsettings.h"

GeneralSettings::GeneralSettings(MainDialog *dialog)
{
	ui.setupUi(this);

	connect(&manager, SIGNAL(finished(QNetworkReply*)),
             SLOT(slotDownloadFinished(QNetworkReply*)));

	connect(ui.autoconnCheckBox, SIGNAL(stateChanged(int)),
		dialog, SLOT(slotToggleAutoConnect(int)));

	connect(ui.resetButton, SIGNAL(clicked()),
		dialog, SLOT(slotResetAccount()));

	connect(ui.checkUpdate, SIGNAL(clicked()),
		this, SLOT(slotCheckUpdate()));

	movie = new QMovie(":/rc/loader.gif");

	ui.versionLabel->setText(QString("Version: %1.").arg(DNCVERSION));

	emit this->slotCheckUpdate();

}

void GeneralSettings::slotCheckUpdate()
{
	ui.updateLabel->setMovie(movie);
	movie->start();

	QUrl url = QUrl::fromUserInput(QString("http://bin.dynvpn.com/dynvpn_stable_version"));
	QNetworkRequest request(url);
	QNetworkReply *reply = manager.get(request);
	currentDownloads.append(reply);
}

void GeneralSettings::slotDownloadFinished(QNetworkReply *reply)
{

	movie->stop();
	ui.updateLabel->clear();

	StableVersion = reply->readAll();
	StableVersion = StableVersion.simplified();
	CurrentVersion = DNCVERSION;

	if (StableVersion > CurrentVersion) {
		ui.updateLabel->setText(QString("<html><head/><body><p>The version %1 is available, please visit <a href=\"https://www.dynvpn.com/download\" target=\"_blank\"><span style=\" text-decoration: underline; color:#0000ff;\">dynvpn.com/download</span></a> to update your client.</p></body></html>").arg(StableVersion));
	} else {
		ui.updateLabel->setText("No updates available. Your installation is at the latest version.");
	}
}

GeneralSettings::~GeneralSettings()
{
	delete movie;
}

void GeneralSettings::slotCheckAutoConnect()
{
	ui.autoconnCheckBox->setChecked(true);
}
