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

#include "generalsettings.h"

GeneralSettings::GeneralSettings(MainDialog *dialog)
{
	ui.setupUi(this);
	connect(ui.autoconnCheckBox, SIGNAL(stateChanged(int)),
		dialog, SLOT(slotToggleAutoConnect(int)));
}

GeneralSettings::~GeneralSettings()
{
}

void GeneralSettings::slotCheckAutoConnect()
{
	ui.autoconnCheckBox->setChecked(true);
}
