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

#include <QLineEdit>

class MyWindow : public QMainWindow
{
	Q_OBJECT

	public:
		MyWindow(QMainWindow *parent = 0, Qt::WFlags fl = Qt::Window);
		QLineEdit *provCode;

	virtual ~MyWindow();

	public slots:
		void connect();

};
