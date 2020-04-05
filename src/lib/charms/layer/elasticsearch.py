#!/usr/bin/env python3
# pylint: disable=c0111,c0103,c0301
import json
import os
import requests
import shutil

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

DISCOVERY_FILE_PATH = ES_PATH_CONF / 'discovery-file' / 'unicast_hosts.txt'

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
    template,
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
    ).get_template(
        str(template)
    ).render(ctxt)

    target.write_text(rendered_template)
    shutil.chown(str(target), user, group)


def elasticsearch_setup_passwords_available():
    """Check elasticsearch-setup-passwords exe is available.
    """

    if os.path.exists(ES_SETUP_PASSWORDS):
        return True
    else:
        # If the the elasticsearch-plugin exe doesn't exist we are in trouble,
        # set workload status to 'blocked' and log.
        status_set(
            'blocked',
            "Cannot find elasticsearch-setup-passwords exe - "
            f"please debug {ES_SETUP_PASSWORDS}"
        )
        log("BAD THINGS - elasticsearch-setup-passwords not available")
        return False


def elasticsearch_plugin_available():
    """Check elasticsearch-plugin exe is available.
    """

    if os.path.exists(ES_PLUGIN):
        return True
    else:
        # If the the elasticsearch-plugin exe doesn't exist we are in trouble,
        # set workload status to 'blocked' and log.
        status_set(
            'blocked',
            "Cannot find elasticsearch plugin manager - "
            f"please debug {ES_PLUGIN}"
        )
        log("BAD THINGS - elasticsearch-plugin not available")
        return False


def restart_elasticsearch():
    # If elasticsearch isn't running start it
    if not service_running('elasticsearch'):
        service_start('elasticsearch')
    # If elasticsearch is running restart it
    else:
        service_restart('elasticsearch')
    # Wait 100 seconds for elasticsearch to restart, then break out of the loop
    # and blocked wil be set below
    cnt = 0
    while not service_running('elasticsearch') and cnt < 100:
        status_set('waiting', 'Waiting for Elasticsearch to start')
        sleep(1)
        cnt += 1

    if service_running('elasticsearch'):
        status_set('active', 'Elasticsearch running')
    else:
        # If elasticsearch wont start, set blocked
        status_set(
            'blocked',
            'There are problems with elasticsearch, please debug'
        )
        return False

    return True
