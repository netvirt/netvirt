#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <QSettings>

class Config {
    public:
        Config();

        QString controllerHost();
        int controllerPort();
        void provision();
        bool isProvisioned();

    protected:
        QSettings *_settings;
};

#endif
