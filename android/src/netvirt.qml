import QtQuick 2.3
import QtQuick.Controls 1.0
import com.netvirt.netvirt 1.0  // injected from C++

ApplicationWindow {
    title: "Netvirt Agent"
    visible: true
    width: 640
    height: 480

    ProvisionWindow {
        id: provisionWindow
        z: -1

        onProvision: netvirtAgent.provision(provKey)
    }

    ConnectWindow {
        id: connectWindow
        z: 1

        onConnect: netvirtAgent.connect_(host, port, secret)
        onDisconnect: netvirtAgent.disconnect_()
    }

    NetvirtAgent {
        id: netvirtAgent
        onConnected: connectWindow.status = "Status: connected"
        onDisconnected: connectWindow.status = "Status: disconnected"
        onProvisioned: {
            provisionWindow.z = -1
            connectWindow.z = 1
        }
    }
}
