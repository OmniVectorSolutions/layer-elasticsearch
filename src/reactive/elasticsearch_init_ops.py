import json
import os
import requests
import subprocess as sp

from base64 import b64encode, b64decode
from pathlib import Path
from requests.auth import HTTPBasicAuth
from time import sleep

import charms.leadership

from charms.reactive import (
    hook,
    is_flag_set,
    set_flag,
    when,
    when_not,
    when_any,
)

from charmhelpers.core import (
    unitdata,
)

from charmhelpers.core.host import (
    chownr,
    fstab_remove,
    is_container,
)

from charmhelpers.core.hookenv import (
    application_version_set,
    config,
    charm_dir,
    is_leader,
    open_port,
    status_set,
)

from charms.layer.elasticsearch import (
    es_active_status,
    elasticsearch_version,
    elasticsearch_plugin_available,
    elasticsearch_exec_cmd,
    gen_password,
    render_elasticsearch_yml,
    render_elasticsearch_file,
    start_restart_systemd_service,
    ES_DATA_DIR,
    ES_NODE_TYPE,
    ES_CLUSTER_INGRESS_ADDRESS,
    ES_HTTP_PORT,
    ES_TRANSPORT_PORT,
    ES_DEFAULT_FILE_PATH,
    ES_CERT_UTIL,
    ES_CA,
    ES_PATH_CONF,
    ES_CERTS_DIR,
    ES_CERTS,
    ES_PLUGIN,
    ES_SETUP_PASSWORDS,
    JAVA_HOME,
    PIP,
)


kv = unitdata.kv()

set_flag('elasticsearch.{}'.format(ES_NODE_TYPE))


if config('xpack-security-enabled'):
    set_flag('xpack.security.enabled')
else:
    set_flag('xpack.security.disabled')


@when('leadership.is_leader')
@when_not('leadership.set.master_ip')
def set_leader_ip_as_master():
    charms.leadership.leader_set(master_ip=ES_CLUSTER_INGRESS_ADDRESS)


@when('leadership.is_leader',
      'xpack.security.enabled')
@when_not('leadership.set.ca_password')
def gen_ca_password():
    charms.leadership.leader_set(ca_password=gen_password())


@when('leadership.is_leader',
      'xpack.security.enabled')
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
    charm code runnig until the start flag has been set.
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


@when(
    'elasticsearch.defaults.available',
    'elasticsearch.ports.available',
    'elasticsearch.juju.started',
    'direct.attached.storage.check.complete',
    'container.check.complete',
    'leadership.set.master_ip',
    'swap.removed',
)
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


@when(
    'elasticsearch.version.set',
    'xpack.security.enabled',
)
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


@when(
    'leadership.is_leader',
    'leadership.set.ca_password',
    'elasticsearch.init.running',
    'xpack.security.enabled',
    'cert.dir.available'
)
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


@when(
    'xpack.security.enabled',
    'leadership.is_leader',
    'leadership.set.cert_password',
    'leadership.set.ca_password',
    'elasticsearch.ca.available',
)
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


@when(
    'xpack.security.enabled',
    'elastic.base.available',
    'leadership.set.cert_password',
    'leadership.set.elasticsearch_certs',
)
@when_not('elasticsearch.keystore.available')
def init_elasticsearch_keystore():
    """Create the keystore
    """

    if not Path("/etc/elasticsearch/elasticsearch.keystore").exists():
        os.environ['ES_PATH_CONF'] = str(ES_PATH_CONF)
        os.environ['JAVA_HOME'] = str(JAVA_HOME)
        sp.call([f"{str(ES_KEYSTORE)}", "create"])
    set_flag('elasticsearch.keystore.available')


@when(
    'xpack.security.enabled',
    'elasticsearch.keystore.available',
    'leadership.set.cert_password',
    'leadership.set.elasticsearch_certs'
)
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


@when(
    'xpack.security.enabled',
    'cert.dir.available',
    'leadership.set.elasticsearch_certs',
)
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


@when_any(
    'elasticsearch.certs.provisioned',
    'xpack.security.disabled',
)
@when(
    'elasticsearch.version.set',
    'elastic.base.available'
)
@when_not(
    'elasticsearch.bootstrapped'
)
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
@when_not('xpack.user.setup.check.complete')
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
    status_set('active', "xpack user setup check complete")
    set_flag('xpack.user.setup.check.complete')


@when_any(
    'leadership.set.users',
    'xpack.security.disabled',
)
@when('xpack.user.setup.check.complete')
@when_not('elasticsearch.init.ops.complete')
def final_sanity_check():
    if config('xpack-security-enabled'):
        users = charms.leadership.leader_get('users')
        auth = HTTPBasicAuth('elastic', json.loads(users)['elastic'])
        resp = requests.get("http://localhost:9200", auth=auth)

    elif not config('xpack-security-enabled'):
        resp = requests.get("http://localhost:9200")

    if resp.status_code == 200:
        set_flag('elasticsearch.init.ops.complete')
        es_active_status()
    else:
        # If elasticsearch wont start, set blocked
        status_set(
            'blocked',
            'There are problems with elasticsearch, please debug'
        )
