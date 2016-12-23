# Overview

Elasticsearch is a flexible and powerful open source, distributed, real-time
search and analytics engine. Architected from the ground up for use in
distributed environments where reliability and scalability are must haves,
Elasticsearch gives you the ability to move easily beyond simple full-text
search. Through its robust set of APIs and query DSLs, plus clients for the
most popular programming languages, Elasticsearch delivers on the near
limitless promises of search technology.

Excerpt from [elasticsearch.org](http://www.elasticsearch.org/overview/ "Elasticsearch Overview")

# Usage

- This charm is the base layer for the different types of ES nodes.
    - Master-eligble node
    - Data node
    - Ingest node
    - Tribe node

- this layer should not be deployed on his own but only serves as a base layer for the ES5 nodes

# Configuration

- Not all the configuration options are implemented yet
- Cluster-name:
    - This can be set in 'config.yaml'

### Provides
- this layer provides a Elasticsearch interface
    - this will add FW rules for Beats and Kibana or other ES clients
```python3
@when('client.connected', 'elasticsearch.configured')
def connect_to_client(connected_clients):
    conf = config()
    cluster_name = conf['cluster-name']
    port = conf['port']
    connected_clients.configure(port, cluster_name)
    clients = connected_clients.list_connected_clients_data
    for c in clients:
        add_fw_exception(c)
```

### Peer
- not implemented yet

# Contact Information

- James Beedy <jamesbeedy@gmail.com>
- Sebastien Pattyn <sebastien.pattyn@gmail.com>

## Elasticsearch

- [Elasticsearch website](http://www.elasticsearch.org/)
