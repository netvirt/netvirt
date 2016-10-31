import logging
import os
import requests
import subprocess
import time

from docker import Client
from hamcrest import assert_that
from hamcrest import contains
from hamcrest import has_entries
from hamcrest import has_entry
from requests import RequestException
from unittest import TestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('docker.auth.auth').setLevel(logging.INFO)

CONTROLLER_PORT = 6388


class DockerCompose(object):
    def __init__(self, asset):
        self._asset = asset
        self._env = {}

    def port(self, container_name, container_port):
        with Client(base_url='unix://var/run/docker.sock') as docker:
            ports = docker.inspect_container(self._container_id(container_name))['NetworkSettings']['Ports']

        exposed_ports = ports.get('{}/tcp'.format(container_port))
        if exposed_ports:
            return int(exposed_ports[0]['HostPort'])
        exposed_ports = ports.get('{}/udp'.format(container_port))
        if exposed_ports:
            return int(exposed_ports[0]['HostPort'])
        raise AssertionError('could not find any port mapped to port {} in container {}'.format(container_port, container_name))

    def up(self, container_name, detach=True):
        detached = ['-d'] if detach else []
        self._run_cmd(['docker-compose', 'up', '--no-color'] + detached + [container_name], env=self._env)

    def kill(self):
        self._run_cmd(['docker-compose', 'kill'])

    def rm(self):
        self._run_cmd(['docker-compose', 'rm', '-f'])

    def set_variable(self, variable, value):
        self._env[variable] = value

    def _run_cmd(self, cmd, stderr=True, env=None):
        current_env = dict(os.environ)
        cmd_env = current_env
        cmd_env.update(env or {})
        with open(os.devnull, "w") as null:
            stderr = subprocess.STDOUT if stderr else null
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr, env=cmd_env)
            out, _ = process.communicate()
        logger.debug('Command output from "%s":\n%s', cmd, out.decode('utf-8'))
        return out

    def _container_id(self, service_name):
        result = self._run_cmd(['docker-compose', 'ps', '-q', service_name], stderr=False).strip()
        result = result.decode('utf-8')
        if '\n' in result:
            raise AssertionError('There is more than one container running with name {}'.format(service_name))
        return result


class MockController(object):
    def __init__(self, host, port):
        self._host = host
        self._port = port

    def ensure_started(self):
        last_exception = None
        for _tries in range(50):
            try:
                logger.debug('Checking controller...')
                self.requests()
            except RequestException as e:
                logger.debug('Controller is down...')
                last_exception = e
                time.sleep(0.1)
            else:
                logger.debug('Controller is up!')
                return
        else:
            raise last_exception

    def requests(self):
        url = 'http://{host}:{port}/_requests'.format(host=self._host, port=self._port)
        response = requests.get(url)
        response.raise_for_status()
        return response.json()


class TestProvisioning(TestCase):

    def setUp(self):
        logger.debug('setUp')
        self.docker_compose = DockerCompose(asset='provision')
        self.docker_compose.up('server', detach=True)
        controller_port = self.docker_compose.port('server', CONTROLLER_PORT)
        self.mock_controller = MockController(host='localhost', port=controller_port)
        self.mock_controller.ensure_started()

    def tearDown(self):
        self.docker_compose.kill()
        self.docker_compose.rm()

    def test_when_provisioning_then_http_request_is_sent(self):
        logger.debug('test')
        self.docker_compose.set_variable('provisioning_key', 'my-key')
        self.docker_compose.up('client', detach=False)

        assert_that(self.mock_controller.requests(), has_entry('requests', contains(
            has_entries({'path': '/provisioning',
                         'body': has_entries({'client_version': '0.6',
                                              'provisioning_key': 'my-key'})}))))
