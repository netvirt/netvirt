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

#include "logsettings.h"

LogSettings::LogSettings()
{
	ui.setupUi(this);
}

LogSettings::~LogSettings()
{
}

void LogSettings::slotUpdateLog(QString logline)
{
	this->ui.logText->insertPlainText(logline);
	this->ui.logText->moveCursor(QTextCursor::End);
}
