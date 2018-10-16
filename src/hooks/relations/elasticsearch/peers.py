from charms.reactive import set_flag, when
from charms.reactive import Endpoint


class ElasticsearchPeer(Endpoint):

    @when('endpoint.{endpoint_name}.joined')
    def peer_joined(self):
        set_flag(self.expand_name('cluster.joined'))

    @when('endpoint.{endpoint_name}.departed')
    def peer_departed(self):
        set_flag(self.expand_name('cluster.departed'))
