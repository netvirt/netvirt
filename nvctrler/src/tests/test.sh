exit_error() {
	printf "\e[0;31m ${testname} \e[0m\n"
#	exit 1
}

EMAIL=`mktemp -u XXXXXX`@example.com
PASSWORD=testpassword
HOST=127.0.0.1:80

###
testname="Create new user"
curl -i -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'","password":"'${PASSWORD}'"}' \
-X POST http://${HOST}/v1/client | grep "201 Created"

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Activate new user"
APIKEY=$(cat /tmp/apikey)
curl -i -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'","apikey":"'${APIKEY}'"}' \
-X POST http://${HOST}/v1/client/activate | grep "200 OK"

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Get new API key"
APIKEY=$(curl -s -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'","password":"'${PASSWORD}'"}' \
-X POST http://${HOST}/v1/client/newapikey | jq -r '.client.apikey')
echo $APIKEY
if [ "${APIKEY}" == "" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Add network"
NET_DESC=`mktemp -u XXXXXX`
SUBNET="10.40.0.0"
NETMASK="255.255.0.0"
curl -i -H 'X-netvirt-apikey: '${APIKEY}'' -H 'Content-Type: application/json' -d '{"description":"'${NET_DESC}'", "subnet":"'${SUBNET}'", "netmask":"'${NETMASK}'"}' \
-X POST http://${HOST}/v1/network

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Add node"
NODE_DESC=`mktemp -u XXXXXX`
curl -i -H 'X-netvirt-apikey: '${APIKEY}'' -H 'Content-Type: application/json' -d '{"network_description":"'${NET_DESC}'", "description":"'${NODE_DESC}'"}' \
-X POST http://${HOST}/v1/node | grep "201 Created"

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Add node2"
NODE_DESC2=`mktemp -u XXXXXX`
curl -i -H 'X-netvirt-apikey: '${APIKEY}'' -H 'Content-Type: application/json' -d '{"network_description":"'${NET_DESC}'", "description":"'${NODE_DESC2}'"}' \
-X POST http://${HOST}/v1/node | grep "201 Created"

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="List regions"
###
curl -s -H 'X-netvirt-apikey: '${APIKEY}'' http://${HOST}/v1/regions
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="List networks"
curl -s -H 'X-netvirt-apikey: '${APIKEY}'' http://${HOST}/v1/network
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Get network UID"
UID=$(curl -s -H 'X-netvirt-apikey: '${APIKEY}'' http://${HOST}/v1/network | jq -r '.networks[0].uid')
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="List nodes"
curl -s -H 'X-netvirt-apikey: '${APIKEY}'' http://${HOST}/v1/node?network_uid=${UID}
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Test resetkey"
curl -i -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'"}' \
-X POST http://${HOST}/v1/client/newresetkey | grep "200 OK"
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

RESETKEY=$(cat /tmp/resetkey)
echo $RESETKEY

###
testname="Reset password"
curl -i -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'", "resetkey":"'${RESETKEY}'", "newpassword":"testpassword"}' \
-X POST http://${HOST}/v1/client/password | grep "200 OK"
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Delete node"
curl -i -H 'X-netvirt-apikey: '${APIKEY}'' \
-X DELETE http://${HOST}/v1/node?description=${NODE_DESC} | grep "204 No Content"
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Delete network"
curl -i -H 'X-netvirt-apikey: '${APIKEY}'' \
-X DELETE  http://${HOST}/v1/network?description=${NET_DESC} | grep "204 No Content"
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi
