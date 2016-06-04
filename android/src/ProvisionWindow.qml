import QtQuick 2.3
import QtQuick.Controls 1.0

Rectangle {
    id: provision

    property var heightUnit: parent.height / 25
    signal provision(string provKey)

    anchors.fill: parent
    anchors.rightMargin: 15/100 * parent.width
    anchors.leftMargin: 15/100 * parent.width
    anchors.topMargin: 15/100 * parent.height
    anchors.bottomMargin: 15/100 * parent.height

    Rectangle {
        id: header

        width: parent.width * 1.5
        height: width / headerImage.ratio

        anchors.top: parent.top
        anchors.left: parent.left

        Image {
            id: headerImage

            property var ratio: 712 / 74

            anchors.fill: parent

            source: "images/header.png"
        }
    }

    Text {
        id: explanation

        anchors.top: header.bottom
        anchors.topMargin: 0.5 * provision.heightUnit

        height: contentHeight
        width: parent.width

        text: "If you don't have a DynVPN account yet, see <a href=\"https://dynvpn.com/gettingstarted\">dynvpn.com/gettingstarted</a> for more info."
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.Wrap
        onLinkActivated: Qt.openUrlExternally(link)
    }

    Rectangle {
        id: provKeyContainer

        width: parent.width
        height: provision.heightUnit

        anchors.top: explanation.bottom
        anchors.topMargin: 0.5 * provision.heightUnit

        Text {
            id: provKeyLabel

            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.left

            text: "Provisioning key"
            verticalAlignment: Text.AlignVCenter
        }

        Rectangle {
            id: provKeyInput

            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: provKeyLabel.right
            anchors.leftMargin: 0.5 * provision.heightUnit
            anchors.right: parent.right

            radius: 5
            border.width: 1
            border.color: "grey"

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
        }
    }
    Rectangle {
        id: buttonContainer

        height: provision.heightUnit

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: provKeyContainer.bottom
        anchors.topMargin: 1.5 * provision.heightUnit
        anchors.rightMargin: provision.heightUnit

        Button {
            id: nextButton

            width: 1.5 * implicitWidth

            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.right: parent.right

            enabled: true  // enabled: false  // pass-through until provisioning is implemented
            text: "Next"
            onClicked: provision.provision(provKey.text)
        }
    }
}
