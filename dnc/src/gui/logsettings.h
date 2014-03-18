/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2014
 * Nicolas J. Bouliane <nib@dynvpn.com>
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

#ifndef LOGSETTINGS_H
#define LOGSETTINGS_H

#include <QDialog>
#include <QString>

#include "ui_logsettings.h"

class LogSettings: public QDialog
{
	Q_OBJECT

	public:
		LogSettings();
		virtual ~LogSettings();

	public slots:
		void slotUpdateLog(QString qline);

	private:
		Ui::LogSettings ui;
};

#endif // LOGSETTINGS_H
