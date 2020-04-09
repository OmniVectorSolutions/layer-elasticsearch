#!/usr/bin/env python3
# pylint: disable=c0111,c0103,c0301
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
    restart_elasticsearch,
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


@hook('data-storage-attached')
def set_storage_available_flag():
    set_flag('elasticsearch.storage.available')


@when('elasticsearch.storage.available',
      'elastic.base.available')
@when_not('elasticsearch.storage.prepared')
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

    set_flag('elasticsearch.storage.prepared')


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
        'root',
        'elasticsearch'
    )
    os.chmod(str(ES_DEFAULT_FILE_PATH), 0o660)

    set_flag('elasticsearch.defaults.available')
    status_set('active', 'Elasticsearch defaults available')


@when('elasticsearch.defaults.available',
      'elasticsearch.ports.available',
      'elasticsearch.juju.started',
      'elasticsearch.storage.prepared',
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

    if restart_elasticsearch():
        sleep(10)
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
        #with open(str(JVM_OPTIONS), 'a') as jvm_options:
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
    elasticsearch_vers = kv.get('elasticsearch_version')
    if int(elasticsearch_vers[0]) < 7:
        if elasticsearch_plugin_available():
            os.environ['ES_PATH_CONF'] = str(ES_PATH_CONF)
            os.environ['JAVA_HOME'] = str(JAVA_HOME)
            sp.call("{} install discovery-file".format(str(ES_PLUGIN)).split())
            set_flag('elasticsearch.discovery.plugin.available')
            discovery_file_location = Path(
                f"{str(ES_PATH_CONF)}/discovery-file/unicast_hosts.txt"
            )
        else:
            log("BAD THINGS - elasticsearch-plugin not available")
            status_set(
                'blocked',
                (
                    "Cannot find elasticsearch plugin manager - "
                    f"please debug {str(ES_PLUGIN)}"
                )
            )
    else:
        discovery_file_location = Path(
            f"{str(ES_PATH_CONF)}/unicast_hosts.txt"
        )
    if is_leader():
        charms.leadership.leader_set(
           discovery_file_location=str(discovery_file_location)
        )
    discovery_file_location.touch()
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

    if restart_elasticsearch():
        sleep(10)
        set_flag('elasticsearch.bootstrapped')


#@when('elasticsearch.init.config.rendered')
#@when_not('elasticsearch.init.running')
#def ensure_elasticsearch_init_started():
#    '''
#    Ensure elasticsearch is started.
#    (this should only run once)
#    '''

#    sp.call(['systemctl', 'daemon-reload'])
#    sp.call(['systemctl', 'enable', 'elasticsearch.service'])

#    if restart_elasticsearch():
#        set_flag('elasticsearch.init.running')


#@when('leadership.is_leader',
#      'elasticsearch.init.config.and.restart.complete')
#@when_not('leadership.set.cluster_bootstrapped')
#def bootstrap_using_leader():



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
        Path(charms.leadership.leader_get('discovery_file_location')),
        {'nodes': nodes}
    )

    clear_flag('render.elasticsearch.unicast-hosts')


#@when('elasticsearch.init.complete')
#@when_not('elasticsearch.final.restart.complete')
#def node_type_all_final_restart_complete():
#    restart_elasticsearch()
#    set_flag('elasticsearch.final.restart.complete')


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


## Node-Type Tribe/Ingest/Data Handlers
#@when_any('elasticsearch.coordinating',
#          'elasticsearch.ingest',
#          'elasticsearch.data')
#@when('elasticsearch.final.restart.complete')
#@when_not('elasticsearch.master.acquired')
#def block_until_master_relation():
#    '''
#    Block non-master node types until we have a master relation.
#
#    (coordinating, ingest, data)
#    '''
#    status_set(
#        'blocked',
#        'Need relation to Elasticsearch master to continue'
#    )
#    return
#
#
#@when('elasticsearch.final.restart.complete',
#      'elasticsearch.master')
#@when_not('elasticsearch.min.masters.available')
#def block_until_min_masters():
#    '''
#    Block master node types from making further progress
#    until we have >= config('min-master-count').
#    '''
#
#    if not (len(kv.get('peer-nodes', [])) >= (config('min-master-count') - 1)):
#        status_set(
#            'blocked',
#            f'Need >= {config("min-master-count")} masters to continue'
#        )
#        return
#    else:
#        set_flag('elasticsearch.min.masters.available')
#
#
## Client Relation
#@when('endpoint.client.joined',
#      f'elasticsearch.{ES_NODE_TYPE}.available')
#def provide_client_relation_data():
#    '''
#    Set client relation data.
#
#    (only 'master' or 'all' type nodes should run this code)
#    '''
#
#    if ES_NODE_TYPE not in ['master', 'all']:
#        log('SOMETHING BAD IS HAPPENING - wronge nodetype for client relation')
#        status_set(
#            'blocked',
#            'Cannot make relation to master - '
#            'wrong node-typeforclient relation, please remove relation'
#        )
#        return
#    else:
#        endpoint_from_flag('endpoint.client.joined').configure(
#            ES_PUBLIC_INGRESS_ADDRESS,
#            ES_HTTP_PORT,
#            ES_CLUSTER_NAME
#        )
#        es_active_status()
#
#
## Non-Master Node Relation
#@when('endpoint.require-master.available')
#def get_all_master_nodes():
#    master_nodes = []
#    endpoint = endpoint_from_flag('endpoint.require-master.available')
#
#    for es in endpoint.list_unit_data():
#        master_nodes.append('{}:{}'.format(es['host'], es['port']))
#
#    kv.set('master-nodes', master_nodes)
#
#    set_flag('render.elasticsearch.unicast-hosts')
#    set_flag('elasticsearch.master.acquired')
#
#
## Master Node Relation
#@when('endpoint.provide-master.joined')
#def provide_master_node_type_relation_data():
#    if not ES_NODE_TYPE == 'master':
#        log('SOMETHING BAD IS HAPPENING - wronge node type for relation')
#        status_set(
#            'blocked',
#            'Cannot make relation to master - wrong node-type for relation'
#        )
#        return
#    else:
#        endpoint_from_flag('endpoint.provide-master.joined').configure(
#            ES_CLUSTER_INGRESS_ADDRESS,
#            ES_TRANSPORT_PORT,
#            ES_CLUSTER_NAME
#        )
#
#
#@when('config.changed.custom-config',
#      'final.sanity.check.complete')
#def render_custom_config_on_config_changed():
#    render_elasticsearch_yml(
#        xpack_security_enabled=config('xpack-security-enabled')
#    )
#    restart_elasticsearch()
#
#
#@hook('upgrade-charm')
#def upgrade_charm_ops():
#    application_version_set(elasticsearch_version())
