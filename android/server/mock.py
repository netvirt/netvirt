import logging

from flask import Flask, jsonify, request
from threading import Thread

LISTEN = '0.0.0.0'
HTTP_PORT = 6388

app = Flask('server_mock')
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

requests_log = []


@app.route('/_requests')
def requests():
    response = {'requests': requests_log}
    return jsonify(response)


@app.route('/1.0/provisioning', methods=['POST'])
def provisioning():
    global requests_log
    provisioning_request = {'path': '/provisioning',
                            'query': [],
                            'body': request.json}
    requests_log.append(provisioning_request)
    logger.debug('request: %s', provisioning_request)

    response = {
        'certificate': None,
        'ca_certificate': None,
        'ip_address': '10.0.0.1'
    }
    return jsonify(response), 200


def main_http():
    app.run(host=LISTEN, port=HTTP_PORT)


def main():
    http_thread = Thread(target=main_http)

    http_thread.start()

    http_thread.join()


if __name__ == '__main__':
    main()
