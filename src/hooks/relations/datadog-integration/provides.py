from charms.reactive import (
    Endpoint,
    set_flag,
    when,
)


class DatadogAgentIntegrationProvides(Endpoint):

    @when('endpoint.{endpoint_name}.joined')
    def joined(self):
        set_flag(self.expand_name('available'))

    def configure(self, integration_name, custom_integration_config=None):
        """
        Configure the datadog-integration relation by providing:
            - integration_name
            - (optional) custom_integration_config
        """

        for relation in self.relations:
            ctxt = {'integration_name': integration_name}
            if custom_integration_config:
                ctxt['custom_integration_config'] = custom_integration_config
            relation.to_publish.update(ctxt)
