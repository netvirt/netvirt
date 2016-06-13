/*
The only purpose of this file is to be able to use qmlscene. For this:
1. comment the injected imports in netvirt.qml
2. run: qmlscene netvirt.qml
*/

import QtQuick 2.3

QtObject {
  signal connect_()
  signal connected()
  onConnect_: connected()

  signal disconnect_()
  signal disconnected()
  onDisconnect_: disconnected()

  signal provision(string provKey)
  signal provisioned()
  onProvision: provisioned()

  signal initialize()
}
