import QtQuick 2.3
import QtQuick.Controls 1.0

Rectangle {
    signal provision(string provKey)

    anchors.fill: parent
    Rectangle {
        id: header
        width: parent.width
        height: 100
        border.width: 1
        border.color: "blue"
    }

    Text {
        id: explanation
        anchors.top: header.bottom
        anchors.topMargin: 15
        anchors.horizontalCenter: parent.horizontalCenter
        text: "If you don't have a DynVPN account yet, see <a href=\"https://dynvpn.com/gettingstarted\">dynvpn.com/gettingstarted</a> for more info."
    }
    Rectangle {
        id: provKeyContainer
        width: parent.width * 2/3
        height: 20
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: explanation.bottom
        anchors.topMargin: 30

        Text {
            id: provKeyLabel
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            text: "Provisioning key"
        }
        Rectangle {
            id: provKeyInput
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: provKeyLabel.right
            anchors.leftMargin: 10
            anchors.right: parent.right
            radius: 5
            TextInput {
                id: provKey
                anchors.fill: parent
                validator: RegExpValidator { regExp: /[0-9abcdef-]{36}/ }
                onEditingFinished: {
                    if (acceptableInput) {
                        nextButton.enabled = true
                    }
                }
            }
            border.width: 1
            border.color: "grey"
        }
        border.width: 1
        border.color: "black"
    }
    Rectangle {
        id: buttonContainer
        height: 40
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: provKeyContainer.bottom
        anchors.margins: 60

        Button {
            id: nextButton
            width: 100
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.right: parent.right
            // enabled: false
            enabled: true
            text: "Next"
            onClicked: provision(provKeyInput.text)
        }
        border.width: 1
        border.color: "red"
    }
    border.width: 5
    border.color: "green"
}
