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

#include "wizarddialog.h"

WizardDialog::WizardDialog(MainDialog *dialog)
{
	ui.setupUi(this);
	this->ui.nextButton->setEnabled(false);

	connect(ui.nextButton, SIGNAL(clicked()), dialog, SLOT(slotWizardNext()));
	connect(ui.cancelButton, SIGNAL(clicked()), dialog, SLOT(slotWizardCancel()));
}

WizardDialog::~WizardDialog()
{
}

void WizardDialog::on_ProvKeyText_textChanged(const QString &text)
{
	if (text.length() != 36)
		this->ui.nextButton->setEnabled(false);
	else {
		this->ui.nextButton->setEnabled(true);
		this->ProvKey = text;
	}
}
