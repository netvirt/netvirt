#ifndef __AGENT_H__
#define __AGENT_H__

#include <QObject>

class NetvirtAgent : public QObject {
        Q_OBJECT

    public:
        NetvirtAgent();

    public slots:
        void connect();
        void disconnect();

    signals:
        void connected();
        void disconnected();
};

#endif
