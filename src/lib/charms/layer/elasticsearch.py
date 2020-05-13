#!/usr/bin/env python3
# pylint: disable=c0111,c0103,c0301
import json
import os
import requests
import shutil
import subprocess as sp

from random import choice

from pathlib import Path
from time import sleep

from jinja2 import Environment, FileSystemLoader

from charmhelpers.core.hookenv import (
    charm_dir,
    config,
    log,
    network_get,
    status_set,
)

from charmhelpers.core import unitdata

from charmhelpers.core.host import (
    is_container,
    service_running,
    service_start,
    service_restart
)

from charms.layer import options


if options.get('basic', 'use_venv'):
    PIP = os.path.join('../.venv', 'bin', 'pip')
else:
    PIP = 'pip3'

ES_HOME_DIR = Path('/usr/share/elasticsearch')

ES_DATA_DIR = Path('/srv/elasticsearch-data')

ES_DEFAULT_FILE_PATH = Path('/etc/default/elasticsearch')

ES_PATH_CONF = Path('/etc/elasticsearch')

ES_YML_PATH = ES_PATH_CONF / 'elasticsearch.yml'

ES_PLUGIN = ES_HOME_DIR / 'bin' / 'elasticsearch-plugin'

ES_SETUP_PASSWORDS = ES_HOME_DIR / 'bin' / 'elasticsearch-setup-passwords'

JVM_OPTIONS = ES_PATH_CONF / 'jvm.options'

JAVA_HOME = Path('/usr/lib/jvm/java-8-openjdk-amd64/jre')

ES_PUBLIC_INGRESS_ADDRESS = network_get('public')['ingress-addresses'][0]

ES_CLUSTER_INGRESS_ADDRESS = network_get('cluster')['ingress-addresses'][0]

ES_NODE_TYPE = config('node-type')

ES_CLUSTER_NAME = config('cluster-name')

ES_HTTP_PORT = 9200

ES_TRANSPORT_PORT = 9300

ES_CERTS_DIR = Path("/etc/elasticsearch/certs")

ES_CA = ES_CERTS_DIR / "ca.p12"

ES_CERTS = ES_CERTS_DIR / "elastic-certificates.p12"

ES_CERT_UTIL = Path('/usr/share/elasticsearch/bin/elasticsearch-certutil')

ES_CA_PASS = "rats"

ES_CERT_PASS = "rats"

ES_KEYSTORE = Path('/usr/share/elasticsearch/bin/elasticsearch-keystore')

CHARM_TEMPLATES = Path(f"{charm_dir()}/templates")

MASTER_NODE_CONFIG = """
node.master: true
node.data: false
node.ingest: false
search.remote.connect: false
"""

DATA_NODE_CONFIG = """
node.master: false
node.data: true
node.ingest: false
search.remote.connect: false
"""

INGEST_NODE_CONFIG = """
node.master: false
node.data: false
node.ingest: true
search.remote.connect: false
"""

COORDINATING_NODE_CONFIG = """
node.master: false
node.data: false
node.ingest: false
search.remote.connect: false
"""

NODE_TYPE_MAP = {
    'all': "",
    'master': MASTER_NODE_CONFIG,
    'data': DATA_NODE_CONFIG,
    'ingest': INGEST_NODE_CONFIG,
    'coordinating': COORDINATING_NODE_CONFIG,
}


kv = unitdata.kv()


def gen_password():
    digits_and_letters = string.ascii_letters + string.digits
    return ''.join(
        choice(digits_and_letters)
        for i in range(len(digits_and_letters))
    )


def es_active_status():
    status_set(
        'active',
        'Elasticsearch Running - {} x {} nodes'.format(
            len(kv.get('peer-nodes', [])) + 1, ES_NODE_TYPE
        )
    )


def render_elasticsearch_yml(
    elasticsearch_yml_template=None,
    extra_ctxt=None
) -> None:
    '''
    Render /etc/elasticsearch/elasticsearch.yml
    '''

    status_set('maintenance', 'Writing /etc/elasticsearch/elasticsearch.yml')

    ctxt = {
        'cluster_name': config('cluster-name'),
        'cluster_network_ip': ES_CLUSTER_INGRESS_ADDRESS,
        'node_type': NODE_TYPE_MAP[config('node-type')],
        'custom_config': config('custom-config'),
        'xpack_security_enabled': 'xpack.security.enabled: {}'.format(
            'true' if config('xpack-security-enabled') else 'false'
        )
    }

    if is_container():
        ctxt['bootstrap_memory_lock'] = \
            kv.get('bootstrap_memory_lock')
        ctxt['discovery_type'] = \
            kv.get('discovery_type')

    if config('xpack-security-enabled'):
        ctxt['xpack_security_transport_ssl_enabled'] = (
            'xpack.security.transport.ssl.enabled: true'
        )
        ctxt['xpack_security_transport_ssl_verification_mode'] = (
            'xpack.security.transport.ssl.verification_mode: certificate'
        )
        ctxt['xpack_security_transport_ssl_keystore_path'] = (
            'xpack.security.transport.ssl.keystore.path: '
            'certs/elastic-certificates.p12'
        )
        ctxt['xpack_security_transport_ssl_truststore_path'] = (
            'xpack.security.transport.ssl.truststore.path: '
            'certs/elastic-certificates.p12'
        )

    if extra_ctxt is not None:
        ctxt = {**ctxt, **extra_ctxt}

    if elasticsearch_yml_template is None:
        elasticsearch_yml_tmpl = "elasticsearch.yml.j2"
    else:
        elasticsearch_yml_tmpl = elasticsearch_yml_template

    render_elasticsearch_file(
        template_name=elasticsearch_yml_tmpl,
        target=ES_YML_PATH,
        ctxt=ctxt
    )


class ElasticsearchError(Exception):
    """Base class for exceptions in this module."""
    pass


class ElasticsearchApiError(ElasticsearchError):
    def __init__(self, message):
        self.message = message


def start_restart(service):
    if service_running(service):
        service_restart(service)
    else:
        service_start(service)


def elasticsearch_version():
    """Return elasticsearch version
    """

    # Poll until elasticsearch has started, otherwise the curl
    # to get the version will error out
    status_code = 0
    counter = 0
    try:
        while status_code != 200 and counter < 100:
            try:
                counter += 1
                log("Polling for elasticsearch api: %d" % counter)
                req = requests.get('http://localhost:9200')
                status_code = req.status_code
                es_curl_data = req.text.strip()
                json_acceptable_data = \
                    es_curl_data.replace("\n", "").replace("'", "\"")
                return json.loads(json_acceptable_data)['version']['number']
            except requests.exceptions.ConnectionError:
                sleep(1)
        log("Elasticsearch needs debugging, cannot access api")
        status_set('blocked', "Cannot access elasticsearch api")
        raise ElasticsearchApiError(
            "%d seconds waiting for es api to no avail" % counter)
    except ElasticsearchApiError as e:
        log(e.message)


def render_elasticsearch_file(
    template_name,
    target,
    ctxt,
    user=None,
    group=None
) -> None:
    if not user and not group:
        user = 'elasticsearch'
        group = 'elasticsearch'
    elif user and not group:
        user = user
        group = user
    elif user and group:
        user = user
        group = group

    # Render template to file
    rendered_template = Environment(
        loader=FileSystemLoader(str(CHARM_TEMPLATES))
    ).get_template(template_name).render(ctxt)

    target.write_text(rendered_template)
    shutil.chown(str(target), user, group)


def elasticsearch_setup_passwords_available():
    """Check elasticsearch-setup-passwords exe is available.
    """

    if ES_SETUP_PASSWORDS.exists():
        return True
    else:
        # If the the elasticsearch-plugin exe doesn't exist we are in trouble,
        # set workload status to 'blocked' and log.
        status_set(
            'blocked',
            "Cannot find elasticsearch-setup-passwords exe - "
            f"please debug {str(ES_SETUP_PASSWORDS)}"
        )
        log("BAD THINGS - elasticsearch-setup-passwords not available")
        return False


def elasticsearch_plugin_available():
    """Check elasticsearch-plugin exe is available.
    """

    if ES_PLUGIN.exists():
        return True
    else:
        # If the the elasticsearch-plugin exe doesn't exist we are in trouble,
        # set workload status to 'blocked' and log.
        status_set(
            'blocked',
            "Cannot find elasticsearch plugin manager - "
            f"please debug {str(ES_PLUGIN)}"
        )
        log("BAD THINGS - elasticsearch-plugin not available")
        return False


def start_restart_systemd_service(systemd_service):
    start_restart(systemd_service)

    # Wait 100 seconds for service to start, then break out of the loop
    # and set blocked status.
    cnt = 0
    while not service_running(systemd_service) and cnt < 100:
        status_set('waiting', f'Waiting for {systemd_service} to start')
        sleep(1)
        cnt += 1

    if service_running(systemd_service):
        status_set('active', f'{systemd_service} running')
    else:
        # If elasticsearch wont start, set blocked
        status_set(
            'blocked',
            f'There are problems with {systemd_service}, please debug'
        )
        return False

    return True


def elasticsearch_exec_cmd(cmd):
    sp.call(["sudo", "-H", "-u", "elasticsearch", "bash", "-c", cmd])
