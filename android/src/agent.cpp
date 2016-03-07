#include "agent.h"

NetvirtAgent::NetvirtAgent() {
}

void NetvirtAgent::connect() {
    emit connected();
}

void NetvirtAgent::disconnect() {
    emit disconnected();
}
