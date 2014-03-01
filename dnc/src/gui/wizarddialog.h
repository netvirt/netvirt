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
