from charms.reactive import Endpoint


class ElasticsearchProvides(Endpoint):

    def configure(self, host, port, cluster_name):
        """
        Configure the elasticsearch relation by providing:
            - host
            - port
            - cluster_name
        """

        for relation in self.relations:
            relation.to_publish.update({
                'cluster_name': cluster_name,
                'host': host,
                'port': port,
            })
