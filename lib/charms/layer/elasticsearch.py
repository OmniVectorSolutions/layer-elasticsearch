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


ES_DATA_DIR = Path('/srv/elasticsearch-data')

ES_PATH_CONF = os.path.join('/', 'etc', 'elasticsearch')

ES_YML_PATH = os.path.join(ES_PATH_CONF, 'elasticsearch.yml')

ES_PUBLIC_INGRESS_ADDRESS = network_get('public')['ingress-addresses'][0]

ES_CLUSTER_INGRESS_ADDRESS = network_get('cluster')['ingress-addresses'][0]

DISCOVERY_FILE_PATH = os.path.join(
    ES_PATH_CONF, 'discovery-file', 'unicast_hosts.txt')

ES_DEFAULT_FILE_PATH = os.path.join('/', 'etc', 'default', 'elasticsearch')

ES_NODE_TYPE = config('node-type')

ES_CLUSTER_NAME = config('cluster-name')

ES_HTTP_PORT = 9200

ES_TRANSPORT_PORT = 9300

ES_PLUGIN = os.path.join(
    '/', 'usr', 'share', 'elasticsearch', 'bin', 'elasticsearch-plugin')

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

NODE_TYPE_MAP = {'all': None,
                 'master': MASTER_NODE_CONFIG,
                 'data': DATA_NODE_CONFIG,
                 'ingest': INGEST_NODE_CONFIG,
                 'coordinating': COORDINATING_NODE_CONFIG}


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


def es_version():
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


def write_es_config(ctxt):
    """Write out /etc/elasticsearch/elasticsearch.yml
    """
    render_elasticsearch_file('elasticsearch.yml.j2', ES_YML_PATH, ctxt)


def render_elasticsearch_file(template, file_path, ctxt,
                              user=None, group=None):
    if not user and not group:
        user = 'elasticsearch'
        group = 'elasticsearch'
    elif user and not group:
        user = user
        group = user
    elif user and group:
        user = user
        group = group

    # Remove file if exists
    if os.path.exists(file_path):
        os.remove(file_path)

    # Spew rendered template into file
    spew(file_path, load_template(template).render(ctxt))

    # Set perms
    chown(os.path.dirname(file_path), user=user, group=group, recursive=True)


def load_template(name, path=None):
    """ load template file
    :param str name: name of template file
    :param str path: alternate location of template location
    """
    if path is None:
        path = os.path.join(charm_dir(), 'templates')
    env = Environment(
        loader=FileSystemLoader(path))
    return env.get_template(name)


def spew(path, data):
    """ Writes data to path
    :param str path: path of file to write to
    :param str data: contents to write
    """
    with open(path, 'w') as f:
        f.write(data)


def chown(path, user, group=None, recursive=False):
    """
    Change user/group ownership of file
    :param path: path of file or directory
    :param str user: new owner username
    :param str group: new owner group name
    :param bool recursive: set files/dirs recursively
    """
    try:
        if not recursive or os.path.isfile(path):
            shutil.chown(path, user, group)
        else:
            for root, dirs, files in os.walk(path):
                shutil.chown(root, user, group)
                for item in dirs:
                    shutil.chown(os.path.join(root, item), user, group)
                for item in files:
                    shutil.chown(os.path.join(root, item), user, group)
    except OSError as e:
        print(e)
