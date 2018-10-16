#!/usr/bin/env python3
# pylint: disable=c0111,c0103,c0301
import os
import subprocess as sp
from time import sleep

from charms.reactive import (
    clear_flag,
    endpoint_from_flag,
    is_flag_set,
    set_flag,
    when,
    when_any,
    when_not,
    hook,
)
from charmhelpers.core.hookenv import (
    application_version_set,
    config,
    log,
    open_port,
    status_set,
)
from charmhelpers.core.host import (
    chownr,
    service_restart,
    service_running,
    service_start,
    fstab_remove
)

from charmhelpers.core import unitdata

from charms.layer.elasticsearch import (
    # pylint: disable=E0611,E0401,C0412
    es_version,
    render_elasticsearch_file,
    DISCOVERY_FILE_PATH,
    ES_DATA_DIR,
    ES_DEFAULT_FILE_PATH,
    ES_PATH_CONF,
    ES_YML_PATH,
    ES_PUBLIC_INGRESS_ADDRESS,
    ES_CLUSTER_INGRESS_ADDRESS,
    ES_CLUSTER_NAME,
    ES_NODE_TYPE,
    ES_HTTP_PORT,
    ES_TRANSPORT_PORT,
    ES_PLUGIN,
    NODE_TYPE_MAP,
    PIP,
)


kv = unitdata.kv()


set_flag('elasticsearch.{}'.format(ES_NODE_TYPE))


def es_active_status():
    status_set('active',
               'Elasticsearch Running - {} x {} nodes'.format(
                   len(kv.get('peer-nodes', [])) + 1, ES_NODE_TYPE))


def render_elasticsearch_yml():
    """
    Render /etc/elasticsearch/elasticsearch.yml
    """

    status_set('maintenance', "Writing /etc/elasticsearch/elasticsearch.yml")

    ctxt = \
        {'cluster_name': config('cluster-name'),
         'cluster_network_ip': ES_CLUSTER_INGRESS_ADDRESS,
         'node_type': NODE_TYPE_MAP[config('node-type')],
         'custom_config': config('custom-config')}

    render_elasticsearch_file('elasticsearch.yml.j2', ES_YML_PATH, ctxt)


@when_not('swap.removed')
def remove_swap():
    """
    Prevent swap
    """
    sp.call(["swapoff", "-a"])
    fstab_remove('none')
    set_flag('swap.removed')


@hook('start')
def set_elasticsearch_started_flag():
    """
    This flag is used to gate against certain
    charm code runnig until the start state has been reached.
    """
    set_flag('elasticsearch.juju.started')


@hook('data-storage-attached')
def set_storage_available_flag():
    set_flag('elasticsearch.storage.available')


@when('elasticsearch.storage.available',
      'elastic.base.available')
@when_not('elasticsearch.storage.prepared')
def prepare_es_data_dir():
    """
    Create (if not exists) and set perms on elasticsearch data dir.
    """

    if not ES_DATA_DIR.exists():
        ES_DATA_DIR.mkdir(parents=True, exist_ok=True)

    chownr(path=str(ES_DATA_DIR), owner='elasticsearch',
           group='elasticsearch', follow_links=True,
           chowntopdir=True)

    set_flag('elasticsearch.storage.prepared')


@when('elastic.base.available')
@when_not('elasticsearch.ports.available')
def open_ports():
    """
    Open port 9200 and 9300
    """
    open_port(ES_HTTP_PORT)
    open_port(ES_TRANSPORT_PORT)
    set_flag('elasticsearch.ports.available')


@when('elastic.base.available')
@when_not('elasticsearch.defaults.available')
def render_elasticsearch_defaults():
    """
    Renders /etc/default/elasticsearch

    The following can be extended to allow additional
    arguments to be added to the /etc/default/elasticsearch.
    """

    ctxt = {}
    if config('java-opts'):
        ctxt['java_opts'] = config('java-opts')

    render_elasticsearch_file(
        'elasticsearch.default.j2',
        ES_DEFAULT_FILE_PATH,
        ctxt,
        'root',
        'elasticsearch'
    )
    os.chmod(ES_DEFAULT_FILE_PATH, 0o660)

    set_flag('elasticsearch.defaults.available')
    status_set('active', "Elasticsearch defaults available")


@when('elastic.base.available')
@when_not('elasticsearch.repository-s3.plugin.available')
def install_repository_s3_plugin():
    """
    Install the repository-s3 plugin.
    """

    if os.path.exists(ES_PLUGIN):
        os.environ['ES_PATH_CONF'] = ES_PATH_CONF
        sp.call("{} install repository-s3".format(ES_PLUGIN).split())
        set_flag('elasticsearch.repository-s3.plugin.available')
    else:
        log("BAD THINGS - elasticsearch-plugin not available")
        status_set('blocked',
                   "Cannot find elasticsearch plugin manager - "
                   "please debug {}".format(ES_PLUGIN))


@when('elastic.base.available')
@when_not('elasticsearch.discovery.plugin.available')
def install_file_based_discovery_plugin():
    """
    Install the file based discovery plugin.
    """

    if os.path.exists(ES_PLUGIN):
        os.environ['ES_PATH_CONF'] = ES_PATH_CONF
        sp.call("{} install discovery-file".format(ES_PLUGIN).split())
        set_flag('elasticsearch.discovery.plugin.available')
    else:
        log("BAD THINGS - elasticsearch-plugin not available")
        status_set('blocked',
                   "Cannot find elasticsearch plugin manager - "
                   "please debug {}".format(ES_PLUGIN))


@when('elasticsearch.repository-s3.plugin.available',
      'elasticsearch.discovery.plugin.available',
      'elasticsearch.defaults.available',
      'elasticsearch.ports.available',
      'elasticsearch.juju.started',
      'elasticsearch.storage.prepared',
      'swap.removed')
@when_not('elasticsearch.init.config.rendered')
def render_config_init():
    render_elasticsearch_yml()
    set_flag('elasticsearch.init.config.rendered')


@when('elasticsearch.init.config.rendered')
@when_not('elasticsearch.init.running')
def ensure_elasticsearch_started():
    """
    Ensure elasticsearch is started.
    (this should only run once)
    """

    sp.call(["systemctl", "daemon-reload"])
    sp.call(["systemctl", "enable", "elasticsearch.service"])

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
        status_set('active', 'Elasticsearch init running')
        set_flag('elasticsearch.init.running')
    else:
        # If elasticsearch wont start, set blocked
        status_set('blocked',
                   "There are problems with elasticsearch, please debug")
        return


@when('elasticsearch.init.running')
@when_not('elasticsearch.version.set')
def get_set_elasticsearch_version():
    """
    Set Elasticsearch version.
    """
    application_version_set(es_version())
    set_flag('elasticsearch.version.set')
    set_flag('elasticsearch.init.complete')


@when('elasticsearch.version.set')
@when_not('pip.elasticsearch.installed')
def install_elasticsearch_pip_dep():
    status_set('maintenance', "Installing Elasticsearch python client.")
    sp.call([PIP, 'install', 'elasticsearch>={}'.format(es_version())])
    status_set('active', "Elasticsearch python client installed.")
    set_flag('pip.elasticsearch.installed')


@when('endpoint.member.joined')
def update_unitdata_kv():
    """
    This handler is ran whenever a peer is joined.
    (all node types use this handler to coordinate peers)
    """

    peers = endpoint_from_flag('endpoint.member.joined').all_units
    if len(peers) > 0 and \
       len([peer._data['private-address']
            for peer in peers if peer._data is not None]) > 0:
        kv.set('peer-nodes',
               [peer._data['private-address']
                for peer in peers if peer._data is not None])
        set_flag('render.elasticsearch.unicast-hosts')


@when('render.elasticsearch.unicast-hosts',
      'elasticsearch.discovery.plugin.available')
def update_discovery_file():
    """
    Update discovery-file
    """

    nodes = []

    if is_flag_set('elasticsearch.all') or is_flag_set('elasticsearch.master'):
        nodes = kv.get('peer-nodes', [])
    else:
        nodes = kv.get('master-nodes', []) + kv.get('peer-nodes', [])

    render_elasticsearch_file(
        'unicast_hosts.txt.j2', DISCOVERY_FILE_PATH, {'nodes': nodes})

    clear_flag('render.elasticsearch.unicast-hosts')


@when('elasticsearch.init.complete')
@when_not('elasticsearch.final.restart.complete')
def node_type_all_final_restart_complete():
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
        set_flag('elasticsearch.final.restart.complete')
        status_set('active', 'Elasticsearch init running')
    else:
        # If elasticsearch wont start, set blocked
        status_set('blocked',
                   "There are problems with elasticsearch, please debug")
        return


@when('elasticsearch.final.restart.complete')
@when_not('elasticsearch.{}.available'.format(ES_NODE_TYPE))
def set_node_type_available_flag():
    set_flag('elasticsearch.{}.available'.format(ES_NODE_TYPE))


@when('elasticsearch.{}.available'.format(ES_NODE_TYPE))
def set_active_status():
    es_active_status()


# Node-Type Tribe/Ingest/Data Handlers
@when_any('elasticsearch.coordinating',
          'elasticsearch.ingest',
          'elasticsearch.data')
@when('elasticsearch.final.restart.complete')
@when_not('elasticsearch.master.acquired')
def block_until_master_relation():
    """
    Block non-master node types until we have a master relation.

    (coordinating, ingest, data)
    """
    status_set('blocked',
               'Need relation to Elasticsearch master to continue')
    return


@when('elasticsearch.final.restart.complete',
      'elasticsearch.master')
@when_not('elasticsearch.min.masters.available')
def block_until_min_masters():
    """
    Block master node types from making further progress
    until we have >= config('min-master-count').
    """

    if not (len(kv.get('peer-nodes', [])) >= (config('min-master-count') - 1)):
        status_set('blocked',
                   'Need >= config("min-master-count") masters to continue')
        return
    else:
        set_flag('elasticsearch.min.masters.available')


# Client Relation
@when('endpoint.client.joined',
      'elasticsearch.{}.available'.format(ES_NODE_TYPE))
# @when_not('juju.elasticsearch.client.joined')
def provide_client_relation_data():
    """
    Set client relation data.

    (only 'master' or 'all' type nodes should run this code)
    """

    if ES_NODE_TYPE not in ['master', 'all']:
        log("SOMETHING BAD IS HAPPENING - wronge nodetype for client relation")
        status_set('blocked',
                   "Cannot make relation to master - "
                   "wrong node-typeforclient relation, please remove relation")
        return
    else:
        status_set('maintenance', "Joining client relation, opening port 9200")
        open_port(ES_HTTP_PORT)
        endpoint_from_flag('endpoint.client.joined').configure(
            ES_PUBLIC_INGRESS_ADDRESS, ES_HTTP_PORT, ES_CLUSTER_NAME)
        es_active_status()
    # set_flag('juju.elasticsearch.client.joined')


# Non-Master Node Relation
@when('endpoint.require-master.available')
def get_all_master_nodes():
    master_nodes = []
    endpoint = endpoint_from_flag('endpoint.require-master.available')

    for es in endpoint.list_unit_data():
        master_nodes.append("{}:{}".format(es['host'], es['port']))

    kv.set('master-nodes', master_nodes)

    set_flag('render.elasticsearch.unicast-hosts')
    set_flag('elasticsearch.master.acquired')


# Master Node Relation
@when('endpoint.provide-master.joined')
def provide_master_node_type_relation_data():
    if not ES_NODE_TYPE == 'master':
        log("SOMETHING BAD IS HAPPENING - wronge node type for relation")
        status_set('blocked',
                   "Cannot make relation to master - "
                   "wrong node-type for relation")
        return
    else:
        endpoint_from_flag('endpoint.provide-master.joined').configure(
            ES_CLUSTER_INGRESS_ADDRESS, ES_TRANSPORT_PORT, ES_CLUSTER_NAME)


@when('endpoint.datadog-integration.available')
@when_not('datadog.integration.relation.info.set')
def set_datadog_integration_relation_info():
    endpoint = endpoint_from_flag('endpoint.datadog-integration.available')
    endpoint.configure(integration_name='elastic')
    set_flag('datadog.integration.relation.info.set')


@when('config.changed.custom-config',
      'elastic.base.available')
def render_custom_config():
    render_elasticsearch_yml()
    if not service_running('elasticsearch'):
        service_start('elasticsearch')
    # If elasticsearch is running restart it
    else:
        service_restart('elasticsearch')


@hook('upgrade-charm')
def upgrade_charm_ops():
    application_version_set(es_version())
