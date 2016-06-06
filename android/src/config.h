#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <QSettings>

class Config {
    public:
        Config();
        void provision();
        bool isProvisioned();

    protected:
        QSettings *_settings;
};

#endif
