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

#include <QDebug>
#include <QUrl>
#include <QNetworkRequest>
#include "generalsettings.h"

GeneralSettings::GeneralSettings(MainDialog *dialog)
{
	ui.setupUi(this);
	connect(ui.autoconnCheckBox, SIGNAL(stateChanged(int)),
		dialog, SLOT(slotToggleAutoConnect(int)));

	connect(ui.resetButton, SIGNAL(clicked()),
		dialog, SLOT(slotResetAccount()));

	ui.versionLabel->setText(QString("Version: %1.").arg(DNCVERSION));

	connect(&manager, SIGNAL(finished(QNetworkReply*)),
             SLOT(slotDownloadFinished(QNetworkReply*)));

	QUrl url = QUrl::fromUserInput(QString("http://bin.dynvpn.com/dynvpn_stable_version"));
	QNetworkRequest request(url);
	QNetworkReply *reply = manager.get(request);
	currentDownloads.append(reply);

}

void GeneralSettings::slotDownloadFinished(QNetworkReply *reply)
{
	StableVersion = reply->readAll();
	StableVersion = StableVersion.simplified();
	CurrentVersion = DNCVERSION;

	if (StableVersion > CurrentVersion) {
		ui.updateLabel->setText(QString("<html><head/><body><p>The version %1 is available, please visit <a href=\"https://www.dynvpn.com/download\" target=\"_blank\"><span style=\" text-decoration: underline; color:#0000ff;\">dynvpn.com/download</span></a> to update your client.</p></body></html>").arg(StableVersion));
	}

}

GeneralSettings::~GeneralSettings()
{
}

void GeneralSettings::slotCheckAutoConnect()
{
	ui.autoconnCheckBox->setChecked(true);
}
