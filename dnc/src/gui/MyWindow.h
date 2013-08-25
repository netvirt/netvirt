/*
 * Dynamic Network Directory Service
 * Copyright (C) 2009-2013
 * Nicolas J. Bouliane <nib@dynvpn.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 */

#include <QtGui/QMainWindow>
#include <QtGui/QPushButton>

#include <QCloseEvent>
#include <QLineEdit>
#include <QMessageBox>
#include <QMenu>
#include <QSystemTrayIcon>

#include "../ui_dnc.h"

class MyWindow : public QMainWindow
{
	Q_OBJECT

	public:
		MyWindow(QMainWindow *parent = NULL, Qt::WFlags fl = Qt::Window);
		static void on_connect(void *obj, const char *ip);

	virtual ~MyWindow();

	public slots:
		void on_prov_key_checkBox_stateChanged(int checked);
		void on_connect_button_clicked();
		void trayIconClicked(QSystemTrayIcon::ActivationReason);

	private:
		void createActions();
		void createTrayIcon();
		void setIcon();
		void closeEvent(QCloseEvent *); // Override the window's close event

		Ui::MainWindow ui;

		QSystemTrayIcon *trayIcon;
		QMenu *trayIconMenu;

		QAction *open;
		QAction *close;
};
