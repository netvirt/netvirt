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
