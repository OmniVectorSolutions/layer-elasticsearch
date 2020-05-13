#!/usr/bin/env python3
import json
import os
import requests
import string

import subprocess as sp

from base64 import b64encode, b64decode
from pathlib import Path
from time import sleep

from requests.auth import HTTPBasicAuth

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

from charmhelpers.core.templating import (
    render,
)

from charmhelpers.core.hookenv import (
    application_version_set,
    charm_dir,
    config,
    is_leader,
    log,
    open_port,
    status_set,
)
from charmhelpers.core.host import (
    chownr,
    is_container,
    service_restart,
    service_running,
    service_start,
    fstab_remove
)

from charmhelpers.core import unitdata

from charms.layer.elasticsearch import (
    # pylint: disable=E0611,E0401,C0412
    gen_password,
    es_active_status,
    elasticsearch_exec_cmd,
    elasticsearch_plugin_available,
    elasticsearch_version,
    render_elasticsearch_file,
    start_restart_systemd_service,
    ES_DATA_DIR,
    ES_DEFAULT_FILE_PATH,
    ES_PATH_CONF,
    ES_YML_PATH,
    ES_PUBLIC_INGRESS_ADDRESS,
    ES_CLUSTER_INGRESS_ADDRESS,
    ES_CLUSTER_NAME,
    ES_NODE_TYPE,
    ES_HTTP_PORT,
    ES_KEYSTORE,
    ES_TRANSPORT_PORT,
    ES_PLUGIN,
    ES_SETUP_PASSWORDS,
    ES_CERTS_DIR,
    ES_CA,
    ES_CERTS,
    ES_CERT_UTIL,
    ES_CA_PASS,
    ES_CERT_PASS,
    JAVA_HOME,
    JVM_OPTIONS,
    NODE_TYPE_MAP,
    PIP,
)

import charms.leadership


kv = unitdata.kv()


@when('elasticsearch.init.ops.complete')
def set_active_status():
    es_active_status()


@when('endpoint.member.joined')
def update_unitdata_kv():
    """
    This handler is ran whenever a peer is joined.
    (all node types use this handler to coordinate peers)
    """

    peers = endpoint_from_flag('endpoint.member.joined').all_joined_units
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
    '''
    Update discovery-file
    '''

    nodes = []

    if is_flag_set('elasticsearch.all') or is_flag_set('elasticsearch.master'):
        nodes = kv.get('peer-nodes', [])
    else:
        nodes = kv.get('master-nodes', []) + kv.get('peer-nodes', [])

    render_elasticsearch_file(
        'unicast_hosts.txt.j2',
        Path(kv.get('discovery_file_location')),
        {'nodes': nodes}
    )

    clear_flag('render.elasticsearch.unicast-hosts')


# Node-Type Tribe/Ingest/Data Handlers
@when_any('elasticsearch.coordinating',
          'elasticsearch.ingest',
          'elasticsearch.data')
@when_not('elasticsearch.master.acquired')
def block_until_master_relation():
    '''
    Block non-master node types until we have a master relation.

    (coordinating, ingest, data)
    '''
    status_set(
        'blocked',
        'Need relation to Elasticsearch master to continue'
    )
    return


# Elastic-Credentials Relation
@when('endpoint.elastic-credentials.joined',
      'leadership.set.users',
      f'elasticsearch.{ES_NODE_TYPE}.available')
@when_not('elastic.credentials.available')
def provide_elastic_user_credentials():
    '''
    Provide elastic user username and password via the
    elastic-credentials interface.

    (only 'master' or 'all' type nodes should run this code)
    '''
    status_set(
        'maintenance',
        'Sending "elastic" user credentials via relation.'
    )

    if ES_NODE_TYPE not in ['master', 'all']:
        log('SOMETHING BAD IS HAPPENING - wronge nodetype for client relation')
        status_set(
            'blocked',
            'Cannot make relation to master - '
            'wrong node-typeforclient relation, please remove relation'
        )
        return
    else:
        ctxt = {}
        users = charms.leadership.leader_get('users')
        ctxt = {
            'username': 'elastic',
            'password': json.loads(users)['elastic']
        }
    endpoint_from_flag('endpoint.elastic-credentials.joined').configure(**ctxt)
    set_flag('elastic.credentials.available')
    es_active_status()


# Kibana Relation
@when('endpoint.kibana-credentials.joined',
      'leadership.set.users',
      f'elasticsearch.{ES_NODE_TYPE}.available')
@when_not('kibana.credentials.available')
def provide_kibana_user_credentials():
    '''
    Provide kibana user credentials via the kibana-credentials
    interface.

    (only 'master' or 'all' type nodes should run this code)
    '''
    status_set(
        'maintenance',
        'Sending "kibana" user credentials via relation.'
    )

    if ES_NODE_TYPE not in ['master', 'all']:
        log('SOMETHING BAD IS HAPPENING - wronge nodetype for client relation')
        status_set(
            'blocked',
            'Cannot make relation to master - '
            'wrong node-type for kibana-credentials relations, please remove '
            'relation.'
        )
        return
    else:
        ctxt = {}
        users = charms.leadership.leader_get('users')
        ctxt = {
            'username': 'kibana',
            'password': json.loads(users)['kibana']
        }

    endpoint_from_flag('endpoint.kibana-credentials.joined').configure(**ctxt)
    set_flag('kibana.credentials.available')
    es_active_status()


@when('leadership.is_leader',
      'endpoint.kibana-host-port.available')
def acquire_kibana_host_port_via_relation():
    """Get kibana host:port from relation, set to leader.
    """
    status_set(
        'maintenance',
        'Acquiring kibana host:port ...'
    )
    endpoint = endpoint_from_flag('endpoint.kibana-host-port.available')

    kibana_host_port = endpoint.list_unit_data()[0]

    host = kibana_host_port['host']
    port = kibana_host_port['port']

    charms.leadership.leader_set(
        monitoring_kibana_host_port=f"{host}:{port}"
    )
    es_active_status()


@when('leadership.is_leader',
      'endpoint.monitoring-credentials.available')
def acquire_monitoring_elasticsearch_user_pass():
    """Get password from elasticsearch monitoring cluster.
    """
    status_set(
        'maintenance',
        'Acquiring monitoring credentials ...'
    )
    endpoint = endpoint_from_flag('endpoint.monitoring-credentials.available')
    password = endpoint.list_unit_data()[0]['password']
    charms.leadership.leader_set(monitoring_elastic_user_password=password)
    es_active_status()


@when('leadership.is_leader',
      'endpoint.monitoring-hosts.available')
def get_set_monitoring_hosts():
    status_set(
        'maintenance',
        'Acquiring monitoring servers ...'
    )
    endpoint = endpoint_from_flag('endpoint.monitoring-hosts.available')
    monitoring_es_servers = ",".join([
        es['host']
        for es in endpoint.list_unit_data()
    ])

    charms.leadership.leader_set(
        monitoring_es_servers=monitoring_es_servers
    )
    es_active_status()


@when('leadership.set.monitoring_kibana_host_port',
      'leadership.set.monitoring_elastic_user_password',
      'leadership.set.monitoring_es_servers',
      'final.sanity.check.complete')
@when_not('elasticsearch.external.monitoring.cluster.configured')
def hookup_the_beats():
    """Configure and enable the monitoring
    to export metrics to the monitoring cluster.
    """
    status_set(
        'maintenance',
        'Configuring monitoring ...'
    )
    kibana_host_port = \
        charms.leadership.leader_get('monitoring_kibana_host_port')
    elastic_user_password = \
        charms.leadership.leader_get('monitoring_elastic_user_password')
    monitoring_es_servers = \
        charms.leadership.leader_get('monitoring_es_servers').split(",")

    ctr = 0
    while requests.get(f"http://{kibana_host_port}").status_code != 200 and\
            ctr <= 100:
        if ctr == 100:
            return
        status_set('waiting', "Waiting on kibana to become available ...")
        sleep(1)
        ctr += 1

    ctxt = {
        'monitoring_kibana_host_port': kibana_host_port,
        'monitoring_elastic_user_password': elastic_user_password,
        'monitoring_es_servers': monitoring_es_servers,
    }

    # Render the metricbeat config, enable the elasticsearch module
    # enable the systemd service, start the service, setup the dashboards.
    render('metricbeat.yml.j2', '/etc/metricbeat/metricbeat.yml', ctxt)

    sp.call(["metricbeat", "modules", "enable", "elasticsearch"])

    sp.call(['systemctl', 'daemon-reload'])

    sp.call(["systemctl", "enable", "metricbeat.service"])

    if is_leader():
        sp.call(["metricbeat", "setup", "--dashboards"])

    # Render the filebeat config, enable the elasticsearch module,
    # enable the systemd service and setup the dashboards.
    render('filebeat.yml.j2', '/etc/filebeat/filebeat.yml', ctxt)

    sp.call(["filebeat", "modules", "enable", "elasticsearch"])

    sp.call(['systemctl', 'daemon-reload'])

    sp.call(['systemctl', 'enable', 'filebeat.service'])

    if is_leader():
        sp.call(["filebeat", "setup"])

    set_flag('elasticsearch.external.monitoring.cluster.configured')
    es_active_status()


@when('elasticsearch.external.monitoring.cluster.configured')
@when_not('elasticsearch.beats.available')
def ensure_beats_are_running():
    status_set(
        'maintenance', f'ensuring beats are fully started'
    )
    for beat in ['filebeat', 'metricbeat']:
        if start_restart_systemd_service(beat):
            status_set(
                'active', f'{beat} has initially started'
            )

            ctr = 0
            beat_record = 0

            while True:
                if ctr == 100:
                    status_set(
                        'blocked',
                        f'{beat} not starting - please debug'
                    )
                    return
                if beat_record == 10:
                    status_set('active', f'{beat} started')
                    set_flag(f'elasticsearch.{beat}.available')
                    break

                status_set(
                    'maintenance',
                    f'ensuring {beat} has fully started'
                )

                if service_running(beat):
                    beat_record += 1
                else:
                    start_restart_systemd_service(beat)
                    beat_record = 0

                ctr += 1
                sleep(1)

    if is_flag_set('elasticsearch.filebeat.available') and\
            is_flag_set('elasticsearch.metricbeat.available'):
        set_flag(f'elasticsearch.beats.available')
    es_active_status()


# Master Node Relation
@when('endpoint.provide-master.joined')
def provide_master_node_type_relation_data():
    if not ES_NODE_TYPE == 'master':
        log('SOMETHING BAD IS HAPPENING - wronge node type for relation')
        status_set(
            'blocked',
            'Cannot make relation to master - wrong node-type for relation'
        )
        return
    else:
        endpoint_from_flag('endpoint.provide-master.joined').configure(
            ES_CLUSTER_INGRESS_ADDRESS,
            ES_TRANSPORT_PORT,
            ES_CLUSTER_NAME
        )


# Client Relation
@when('endpoint.client.joined',
      f'elasticsearch.{ES_NODE_TYPE}.available')
def provide_client_relation_data():
    '''
    Set client relation data.

    (only 'master' or 'all' type nodes should run this code)
    '''

    status_set(
        'maintenance',
        'Client relation joined, sending elasticsearch cluster data to client.'
    )

    if ES_NODE_TYPE not in ['master', 'all']:
        log('SOMETHING BAD IS HAPPENING - wronge nodetype for client relation')
        status_set(
            'blocked',
            'Cannot make relation to master - '
            'wrong node-typeforclient relation, please remove relation'
        )
        return
    else:
        endpoint_from_flag('endpoint.client.joined').configure(
            ES_PUBLIC_INGRESS_ADDRESS,
            ES_HTTP_PORT,
            ES_CLUSTER_NAME
        )
        es_active_status()


# Non-Master Node Relation
@when('endpoint.require-master.available')
def get_all_master_nodes():
    master_nodes = []
    endpoint = endpoint_from_flag('endpoint.require-master.available')

    for es in endpoint.list_unit_data():
        master_nodes.append('{}:{}'.format(es['host'], es['port']))

    kv.set('master-nodes', master_nodes)

    set_flag('render.elasticsearch.unicast-hosts')
    set_flag('elasticsearch.master.acquired')


@when('config.changed.custom-config',
      'final.sanity.check.complete')
def render_custom_config_on_config_changed():
    render_elasticsearch_yml()
    if start_restart_systemd_service('elasticsearch'):
        status_set('active', "Success changing config")
