import QtQuick 2.3
import QtQuick.Controls 1.0

Rectangle {
    anchors.fill: parent

    property alias status: status.text
    property alias host: host.text
    property alias port: port.text
    property alias secret: secret.text
    signal connect(string host, string port, string secret)
    signal disconnect()

    Column {
        id: column
        spacing: 20
        anchors.centerIn: parent

        Text {
            id: status
            text: "Status: disconnected"
        }

        TextInput {
            id: host
            text: "192.168.1.90"
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
            onClicked: connect(host.text, port.text, secret.text)
        }

        Button {
            id: disconnectButton
            text: "Disconnect"
            onClicked: disconnect()
        }
    }
}
