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

#ifndef WIZARDDIALOG_H
#define WIZARDDIALOG_H

#include <QDialog>

#include "maindialog.h"
#include "ui_wizarddialog.h"

class WizardDialog: public QDialog
{
	Q_OBJECT

	public:
		WizardDialog(MainDialog *dialog);
		virtual ~WizardDialog();
		QString ProvKey;

	public slots:
		void on_ProvKeyText_textChanged(const QString &text);

	private:
		Ui::WizardDialog ui;
};

#endif // WIZARDDIALOG
