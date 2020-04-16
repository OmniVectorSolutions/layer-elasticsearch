#!/usr/bin/env python3
import json
import os
import requests
import string

import subprocess as sp

from base64 import b64encode, b64decode
from pathlib import Path
from time import sleep
from random import choice

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


set_flag('elasticsearch.{}'.format(ES_NODE_TYPE))


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


@when_not('leadership.set.ca_password')
def gen_ca_password():
    charms.leadership.leader_set(ca_password=gen_password())


@when_not('leadership.set.cert_password')
def gen_cert_password():
    charms.leadership.leader_set(cert_password=gen_password())


@when_not('container.check.complete')
def confiugre_vm_max_heap():
    bootstrap_memory_lock = 'bootstrap.memory_lock: false'
    if is_container():
        kv.set('discovery_type', 'discovery.type: single-node')
        bootstrap_memory_lock = 'bootstrap.memory_lock: true'
    kv.set('bootstrap_memory_lock', bootstrap_memory_lock)
    set_flag('container.check.complete')


@when('leadership.is_leader')
@when_not('leadership.set.master_ip')
def set_leader_ip_as_master():
    charms.leadership.leader_set(master_ip=ES_CLUSTER_INGRESS_ADDRESS)


@when_not('swap.removed')
def remove_swap():
    '''
    Prevent swap
    '''
    sp.call(['swapoff', '-a'])
    fstab_remove('none')
    set_flag('swap.removed')


@hook('start')
def set_elasticsearch_started_flag():
    '''
    This flag is used to gate against certain
    charm code runnig until the start state has been reached.
    '''
    set_flag('elasticsearch.juju.started')


@when('elastic.base.available')
@when_not('elasticsearch.storage.dir.prepared')
def prepare_es_data_dir():
    '''
    Create (if not exists) and set perms on elasticsearch data dir.
    '''

    if not ES_DATA_DIR.exists():
        ES_DATA_DIR.mkdir(parents=True, exist_ok=True)

    chownr(
        path=str(ES_DATA_DIR),
        owner='elasticsearch',
        group='elasticsearch',
        follow_links=True,
        chowntopdir=True
    )

    set_flag('elasticsearch.storage.dir.prepared')


# @hook('data-storage-attached')
# def set_storage_available_flag():
#    set_flag('elasticsearch.storage.available')


@when('elasticsearch.storage.dir.prepared')
@when_not('direct.attached.storage.check.complete')
def check_for_and_mount_direct_attached_storage():
    direct_attached_device = Path('/dev/nvme0n1')
    if direct_attached_device.exists():
        sp.call(
            [
                'mkfs.ext4',
                str(direct_attached_device)
            ]
        )
        sp.call(
            [
                'mount',
                str(direct_attached_device),
                str(ES_DATA_DIR)
            ]
        )

        chownr(
            path=str(ES_DATA_DIR),
            owner='elasticsearch',
            group='elasticsearch',
            follow_links=True,
            chowntopdir=True
        )

        with open('/etc/fstab', 'a') as f:
            f.write(
                (
                    f'/dev/nvme0n1 {str(ES_DATA_DIR)} '
                    'ext4 defaults,nofail 0 2'
                )
            )

    set_flag('direct.attached.storage.check.complete')


@when('elastic.base.available')
@when_not('elasticsearch.ports.available')
def open_ports():
    '''
    Open port 9200 and 9300
    '''
    open_port(ES_HTTP_PORT)
    open_port(ES_TRANSPORT_PORT)
    set_flag('elasticsearch.ports.available')


@when('elastic.base.available')
@when_not('elasticsearch.defaults.available')
def render_elasticsearch_defaults():
    '''
    Renders /etc/default/elasticsearch

    The following can be extended to allow additional
    arguments to be added to the /etc/default/elasticsearch.
    '''

    ctxt = {}
    if config('java-opts'):
        ctxt['java_opts'] = config('java-opts')

    render_elasticsearch_file(
        'elasticsearch.default.j2',
        ES_DEFAULT_FILE_PATH,
        ctxt,
        'elasticsearch',
        'root',
    )
    os.chmod(str(ES_DEFAULT_FILE_PATH), 0o660)

    set_flag('elasticsearch.defaults.available')
    status_set('active', 'Elasticsearch defaults available')


@when('elasticsearch.defaults.available',
      'elasticsearch.ports.available',
      'elasticsearch.juju.started',
      'direct.attached.storage.check.complete',
      'container.check.complete',
      'leadership.set.master_ip',
      'swap.removed')
@when_not('elasticsearch.init.running')
def render_bootstrap_config():
    '''Render the bootstrap elasticsearch.yml and restart.
    '''
    ctxt = {
        'extra_ctxt': {
            'xpack_security_enabled': 'xpack.security.enabled: false',
            'bootstrap_memory_lock': kv.get('bootstrap_memory_lock'),
        },
        'elasticsearch_yml_template': 'elasticsearch-bootstrap.yml.j2',
    }

    if is_container():
        ctxt['extra_ctxt']['discovery_type'] = kv.get('discovery_type')
    else:
        ctxt['extra_ctxt']['cluster_initial_master_nodes'] = [
            charms.leadership.leader_get('master_ip')
        ]

    render_elasticsearch_yml(**ctxt)

    sp.call(['systemctl', 'daemon-reload'])
    sp.call(['systemctl', 'enable', 'elasticsearch.service'])

    if start_restart_systemd_service('elasticsearch'):
        sleep(1)
        set_flag('elasticsearch.init.running')


@when_not('elasticsearch.version.set')
@when('elasticsearch.init.running')
def get_set_elasticsearch_version():
    '''
    Set Elasticsearch version.
    '''
    elasticsearch_vers = elasticsearch_version()
    kv.set('elasticsearch_version', elasticsearch_vers)
    application_version_set(elasticsearch_vers)
    set_flag('elasticsearch.version.set')


@when('elasticsearch.version.set')
@when_not('pip.elasticsearch.installed')
def install_elasticsearch_pip_dep():
    status_set('maintenance', 'Installing Elasticsearch python client.')
    sp.call([PIP, 'install', f'elasticsearch=={elasticsearch_version()[0]}'])
    status_set('active', 'Elasticsearch python client installed.')
    set_flag('pip.elasticsearch.installed')


@when('elasticsearch.version.set')
@when_not('cert.dir.available')
def create_certs_dir():
    if not ES_CERTS_DIR.exists():
        ES_CERTS_DIR.mkdir()
    chownr(
        path=str(ES_CERTS_DIR),
        owner='elasticsearch',
        group='elasticsearch',
        follow_links=True,
        chowntopdir=True
    )
    set_flag('cert.dir.available')


@when('leadership.is_leader',
      'leadership.set.ca_password',
      'elasticsearch.init.running',
      'cert.dir.available')
@when_not('elasticsearch.ca.available')
def provision_elasticsearch_local_ca():
    ca_pass = charms.leadership.leader_get('ca_password')

    cmd = (
            f"ES_PATH_CONF={str(ES_PATH_CONF)} "
            f"{str(ES_CERT_UTIL)} ca "
            f"--out {str(ES_CA)} "
            f"--pass {ca_pass}"
    )
    elasticsearch_exec_cmd(cmd)
    set_flag('elasticsearch.ca.available')


@when('leadership.is_leader',
      'leadership.set.cert_password',
      'leadership.set.ca_password',
      'elasticsearch.ca.available')
@when_not('leadership.set.elasticsearch_certs')
def provision_elasticsearch_certs():
    """Generate certificate password
    """
    cert_pass = charms.leadership.leader_get('cert_password')
    ca_pass = charms.leadership.leader_get('ca_password')

    cmd = (
            f"ES_PATH_CONF={str(ES_PATH_CONF)} "
            f"{str(ES_CERT_UTIL)} cert "
            f"--ca {str(ES_CA)} --out {str(ES_CERTS)} "
            f"--pass {cert_pass} "
            f"--ca-pass {ca_pass}"
    )
    elasticsearch_exec_cmd(cmd)

    charms.leadership.leader_set(
        elasticsearch_certs=b64encode(ES_CERTS.read_bytes()).decode()
    )


@when('elastic.base.available',
      'leadership.set.cert_password',
      'leadership.set.elasticsearch_certs')
@when_not('elasticsearch.keystore.available')
def init_elasticsearch_keystore():
    """Create the keystore
    """

    if not Path("/etc/elasticsearch/elasticsearch.keystore").exists():
        os.environ['ES_PATH_CONF'] = str(ES_PATH_CONF)
        os.environ['JAVA_HOME'] = str(JAVA_HOME)
        sp.call([f"{str(ES_KEYSTORE)}", "create"])
    set_flag('elasticsearch.keystore.available')


@when('elasticsearch.keystore.available',
      'leadership.set.cert_password',
      'leadership.set.elasticsearch_certs')
@when_not('elasticsearch.ssl.keystore.available')
def init_ssl_keystore():
    """Init keystore with transport ssl key
    """
    cert_pass = charms.leadership.leader_get('cert_password')
    sp.call(
        [f"{charm_dir()}/scripts/set_transport_keystore_values.sh", cert_pass]
    )
    set_flag('elasticsearch.ssl.keystore.available')


@when('elasticsearch.version.set')
@when_not('elasticsearch.repository-s3.plugin.available')
def install_repository_s3_plugin():
    '''
    Install the repository-s3 plugin.
    '''

    if elasticsearch_plugin_available():
        # Fix /etc/elasticsearch/jvm.options
        # with open(str(JVM_OPTIONS), 'a') as jvm_options:
        #    jvm_options.write('-Des.allow_insecure_settings=true')
        # Set environment variables needed to run elasticsearch-plugin cmd
        os.environ['ES_PATH_CONF'] = str(ES_PATH_CONF)
        os.environ['JAVA_HOME'] = str(JAVA_HOME)
        # Call elasticsearch-plugin install
        sp.call(f'{str(ES_PLUGIN)} install repository-s3 -b -s'.split())
        set_flag('elasticsearch.repository-s3.plugin.available')


@when('elasticsearch.version.set')
@when_not('elasticsearch.discovery.plugin.available')
def install_file_based_discovery_plugin():
    """
    Install the file based discovery plugin.
    """
    # Initial check to make sure elasticsearch-plugin is available
    if not elasticsearch_plugin_available():
        log("BAD THINGS - elasticsearch-plugin not available")
        status_set(
            'blocked',
            (
                "Cannot find elasticsearch plugin manager - "
                f"please debug {str(ES_PLUGIN)}"
            )
        )
        return

    if int(kv.get('elasticsearch_version')[0]) < 7:
        if elasticsearch_plugin_available():
            os.environ['ES_PATH_CONF'] = str(ES_PATH_CONF)
            os.environ['JAVA_HOME'] = str(JAVA_HOME)
            sp.call("{} install discovery-file".format(str(ES_PLUGIN)).split())
            discovery_file_location = Path(
                f"{str(ES_PATH_CONF)}/discovery-file/unicast_hosts.txt"
            )
    else:
        discovery_file_location = Path(
            f"{str(ES_PATH_CONF)}/unicast_hosts.txt"
        )
    discovery_file_location.touch()
    kv.set('discovery_file_location', str(discovery_file_location))
    set_flag('elasticsearch.discovery.plugin.available')


@when('elasticsearch.repository-s3.plugin.available',
      'elasticsearch.discovery.plugin.available')
@when_not('elasticsearch.plugins.available')
def set_plugins_available():
    set_flag('elasticsearch.plugins.available')


@when('cert.dir.available',
      'leadership.set.elasticsearch_certs')
@when_not('elasticsearch.certs.provisioned')
def provision_certs_all_nodes():
    certs = charms.leadership.leader_get('elasticsearch_certs')
    ES_CERTS.write_bytes(b64decode(certs))
    chownr(
        path=str(ES_CERTS),
        owner='elasticsearch',
        group='elasticsearch',
        follow_links=True,
        chowntopdir=True
    )
    set_flag('elasticsearch.certs.provisioned')


@when('elasticsearch.init.running',
      'elasticsearch.ssl.keystore.available',
      'elasticsearch.certs.provisioned',
      'elasticsearch.plugins.available')
@when_not('elasticsearch.bootstrapped')
def render_config_post_bootstrap_init():
    '''Render the bootstrap elasticsearch.yml and restart.
    '''

    render_elasticsearch_yml()

    if start_restart_systemd_service('elasticsearch'):
        sleep(1)
        set_flag('elasticsearch.bootstrapped')


@when('elasticsearch.bootstrapped')
@when_not(f'elasticsearch.{ES_NODE_TYPE}.available')
def set_node_type_available_flag():
    set_flag(f'elasticsearch.{ES_NODE_TYPE}.available')


@when(f'elasticsearch.{ES_NODE_TYPE}.available')
@when_not('xpack.security.check.complete')
def check_for_and_configure_xpack_security():
    master_or_all = \
        is_flag_set('elasticsearch.master') or is_flag_set('elasticsearch.all')

    if is_leader() and master_or_all and config('xpack-security-enabled'):

        # Set environment variables needed to run elasticsearch-setup-passwords
        os.environ['ES_PATH_CONF'] = str(ES_PATH_CONF)
        os.environ['JAVA_HOME'] = str(JAVA_HOME)

        out = sp.check_output(
            f'{str(ES_SETUP_PASSWORDS)} auto -b'.split()
        ).decode().rstrip()

        users = {}
        for line in out.split('\n'):
            if 'PASSWORD' in line:
                user = line.split()[1]
                password = line.split()[3]
                users[user] = password
        charms.leadership.leader_set(users=json.dumps(users))
    status_set('active', "security check complete")
    set_flag('xpack.security.check.complete')


@when('leadership.set.users',
      'xpack.security.check.complete')
@when_not('final.sanity.check.complete')
def final_sanity_check():
    master_or_all = \
        is_flag_set('elasticsearch.master') or is_flag_set('elasticsearch.all')

    if config('xpack-security-enabled') and master_or_all:
        users = charms.leadership.leader_get('users')
        auth = HTTPBasicAuth('elastic', json.loads(users)['elastic'])
        resp = requests.get("http://localhost:9200", auth=auth)
    else:
        resp = requests.get("http://localhost:9200")

    if resp.status_code == 200:
        set_flag('final.sanity.check.complete')
        es_active_status()
    else:
        # If elasticsearch wont start, set blocked
        status_set(
            'blocked',
            'There are problems with elasticsearch, please debug'
        )
        return False
    return True


@when('xpack.security.check.complete')
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
