import QtQuick 2.3
import QtQuick.Controls 1.0
import com.netvirt.netvirt 1.0

// netvirt_agent injected via rootContext()

ApplicationWindow {
    title: "Netvirt Agent"
    visible: true
    width: 640
    height: 480

    Column {
        spacing: 20
        width: 100
        height: 60
        anchors.centerIn: parent

        Text {
            id: status
            text: "Status: disconnected"
        }

        TextInput {
            id: host
            text: "10.0.0.1"
        }

        TextInput {
            id: port
            text: "8000"
        }

        TextInput {
            id: secret
            text: "test"
        }

        Button {
            id: connectButton
            text: "Connect"
            onClicked: netvirtAgent.connect_(host.text, port.text, secret.text)
        }

        Button {
            id: disconnectButton
            text: "Disconnect"
            onClicked: netvirtAgent.disconnect_()
        }
    }

    NetvirtAgent {
        id: netvirtAgent
        onConnected: status.text = "Status: connected"
        onDisconnected: status.text = "Status: disconnected"
    }
}
