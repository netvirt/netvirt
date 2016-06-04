import QtQuick 2.3
import QtQuick.Controls 1.0

Rectangle {
    id: connect

    property var heightUnit: parent.height / 25
    property alias status: status.text
    property alias host: host.text
    property alias port: port.text
    property alias secret: secret.text
    signal connect(string host, string port, string secret)
    signal disconnect()
    signal connected(string newIpAddress)
    signal disconnected()

    onConnected: {
        statusIcon.source = "images/connected.png"
        status.text = "Now connected"
        ipAddress.text = newIpAddress
        ipAddressBox.visible = true
    }

    onDisconnected: {
        statusIcon.source = "images/disconnected.png"
        status.text = "Not connected"
        ipAddress.text = "<none>"
        ipAddressBox.visible = false
    }

    anchors.fill: parent
    anchors.rightMargin: 15/100 * parent.width
    anchors.leftMargin: 15/100 * parent.width
    anchors.topMargin: 15/100 * parent.height
    anchors.bottomMargin: 15/100 * parent.height

    Rectangle {
        id: header

        height: 2 * connect.heightUnit

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right

        Rectangle {
            id: statusBox

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: logo.left
            anchors.bottom: parent.bottom

            Image {
                id: statusIcon

                property var ratio: 1

                width: ratio * height

                anchors.top: parent.top
                anchors.left: parent.left
                anchors.bottom: parent.bottom

                source: "images/disconnected.png"
            }

            Text {
                id: status

                anchors.top: parent.top
                anchors.left: statusIcon.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: statusIcon.width / 3

                font.pointSize: 32
                font.bold: true

                text: "Not connected"
                verticalAlignment: Text.AlignVCenter
            }
        }

        Image {
            id: logo

            property var ratio: 1

            width: ratio * height

            anchors.top: parent.top
            anchors.right: parent.right
            anchors.bottom: parent.bottom

            source: "images/logo.svg"
        }

    }

    Rectangle {
        id: separator

        height: connect.heightUnit / 20
        width: parent.width * 2

        anchors.top: header.bottom
        anchors.horizontalCenter: parent.horizontalCenter

        anchors.topMargin: connect.heightUnit / 2

        color: "#DDDDDD"
    }

    Button {
        id: connectButton

        height: connect.heightUnit * 2
        width: parent.width / 3

        anchors.top: separator.bottom
        anchors.horizontalCenter: parent.horizontalCenter

        anchors.topMargin: connect.heightUnit

        text: "Connect"

        onClicked: connect.connect(host.text, port.text, secret.text)
    }

    Rectangle {
        id: ipAddressBox

        width: ipAddressLabel.contentWidth + connect.heightUnit / 5 + ipAddress.contentWidth
        height: connect.heightUnit

        anchors.top: connectButton.bottom
        anchors.horizontalCenter: parent.horizontalCenter

        anchors.topMargin: connect.heightUnit

        Text {
            id: ipAddressLabel

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.bottom: parent.bottom

            text: "Your IP address :"
            verticalAlignment: Text.AlignVCenter
        }

        Text {
            id: ipAddress

            anchors.top: parent.top
            anchors.right: parent.right
            anchors.bottom: parent.bottom

            // text: "<none>"
            text: "10.0.0.2"
            verticalAlignment: Text.AlignVCenter

            font.pointSize: 24
            font.bold: true
        }

        visible: false
    }

    Column {
        id: column
        spacing: 20
        anchors.bottom: parent.bottom
        visible: false

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
            id: disconnectButton
            text: "Disconnect"
            onClicked: disconnect()
        }
    }
}
