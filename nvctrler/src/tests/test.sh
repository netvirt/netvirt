exit_error() {
	printf "\e[0;31m ${testname} \e[0m\n"
#	exit 1
}

EMAIL=test@example.com
PASSWORD=testpassword

###
testname="Create new user"
curl -i -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'","password":"'${PASSWORD}'"}' \
-X POST http://127.0.0.1:8080/v1/client | grep "201 Created"

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Activate new user"
APIKEY=$(cat /tmp/apikey)
curl -i -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'","apikey":"'${APIKEY}'"}' \
-X POST http://127.0.0.1:8080/v1/client/activate | grep "200 OK"

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Get new API key"
APIKEY=$(curl -s -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'","password":"'${PASSWORD}'"}' \
-X POST http://127.0.0.1:8080/v1/client/newapikey | jq -r '.client.apikey')
echo $APIKEY
if [ "${APIKEY}" == "" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Add network"
NET_DESC="home-network"
SUBNET="10.40.0.0"
NETMASK="255.255.0.0"
curl -i -H 'X-netvirt-apikey: '${APIKEY}'' -H 'Content-Type: application/json' -d '{"description":"'${NET_DESC}'", "subnet":"'${SUBNET}'", "netmask":"'${NETMASK}'"}' \
-X POST http://127.0.0.1:8080/v1/network

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Add node"
NODE_DESC="pc-home"
curl -i -H 'X-netvirt-apikey: '${APIKEY}'' -H 'Content-Type: application/json' -d '{"network_description":"'${NET_DESC}'", "description":"'${NODE_DESC}'"}' \
-X POST http://127.0.0.1:8080/v1/node | grep "201 Created"

if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="List networks"
curl -s -H 'X-netvirt-apikey: '${APIKEY}'' http://127.0.0.1:8080/v1/network
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Get network UID"
UID=$(curl -s -H 'X-netvirt-apikey: '${APIKEY}'' http://127.0.0.1:8080/v1/network | jq -r '.networks[0].uid')
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="List nodes"
curl -s -H 'X-netvirt-apikey: '${APIKEY}'' http://127.0.0.1:8080/v1/node?network_uid=${UID}
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi

###
testname="Test resetkey"
curl -i -H 'Content-Type: application/json' -d '{"email":"'${EMAIL}'"}' \
-X POST http://127.0.0.1:8080/v1/client/newresetkey | grep "200 OK"
if [ "$?" != "0" ]; then
	exit_error
else
	printf "\e[0;32m ${testname} \e[0m\n"
fi
