#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <QString>

void log_info(const char *string);  // see native_* for implementation
void log_info(const QByteArray& string);  // see native_* for implementation
void log_info(const QString& string);  // see native_* for implementation

#endif
