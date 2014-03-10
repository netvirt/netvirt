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

#ifndef MAINDIALOG_H
#define MAINDIALOG_H

#include <QDesktopWidget>
#include <QDialog>
#include <QMessageBox>
#include <QSize>
#include <QString>
#include <QSystemTrayIcon>

#include "ui_maindialog.h"

class AccountSettings;
class LogSettings;
class GeneralSettings;
class WizardDialog;

class MainDialog: public QDialog
{
	Q_OBJECT

	public:
		MainDialog();
		virtual ~MainDialog();

		/* Interface between C backend and Qt GUI */
		static void onLog(const char *);
		static void onConnect(const char *ip);
		static void onDisconnect();

	public slots:
		void slotExit();
		void slotWizardCancel();
		void slotWizardNext();
		void slotToggleAutoConnect(int);
		void slotFireConnection();
		void slotResetAccount();
		void trayIconClicked(QSystemTrayIcon::ActivationReason);

	private:
		Ui::MainDialog ui;

		AccountSettings *accountSettings;
		LogSettings *logSettings;
		GeneralSettings *generalSettings;
		WizardDialog *wizardDialog;

		QString ProvKey;
		QSystemTrayIcon *trayIcon;
	
		void NowRun();	
		void createTrayIcon();
		void setTrayIcon();

		/* Override the window's close event */
		void closeEvent(QCloseEvent *);
		void centerWidget(QWidget *w);
};

#endif // MAINDIALOG
