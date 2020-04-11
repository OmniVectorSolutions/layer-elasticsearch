# VARIABLES
export PATH := /snap/bin:$(PATH)
export CHARM_NAME := elasticsearch
export CHARM_STORE_GROUP := omnivector
export CHARM_BUILD_DIR := ./build/builds
export CHARM_DEPS_DIR := ./build/deps
export CHARM_PUSH_RESULT := charm-store-push-result.txt

# TARGETS
init: ## Init layers and interfaces
	rm -rf layers
	rm -rf interfaces
	mkdir layers interfaces
	ssh-agent bash -c 'ssh-add  ~/.ssh/id_rsa; git clone git@github.com:omnivector-solutions/layer-elastic-base layers/elastic-base'
	ssh-agent bash -c 'ssh-add  ~/.ssh/id_rsa; git clone git@github.com:omnivector-solutions/interface-elasticsearch-user-credentials interfaces/elasticsearch-user-credentials'
	ssh-agent bash -c 'ssh-add  ~/.ssh/id_rsa; git clone git@github.com:omnivector-solutions/interface-host-port interfaces/host-port'
	ssh-agent bash -c 'ssh-add  ~/.ssh/id_rsa; git clone git@github.com:omnivector-solutions/interface-elasticsearch interfaces/elasticsearch'

lint: ## Run linter
	tox -e lint

smoke-test: build ## Run smoke tests
	tox -e smoke

integration-test: build ## Run integration tests
	tox -e integration

build: clean ## Build charm
	tox -e build

deploy: build ## Deploy charm 
	juju deploy $(CHARM_BUILD_DIR)/$(CHARM_NAME)

upgrade: build ## Upgrade charm
	juju upgrade-charm $(CHARM_NAME) --path $(CHARM_BUILD_DIR)/$(CHARM_NAME)

force-upgrade: build ## Force upgrade charm
	juju upgrade-charm $(CHARM_NAME) --path $(CHARM_BUILD_DIR)/$(CHARM_NAME) --force-units

push: build ## Push and release charm to edge channel on charm store
	# See bug for why we can't push straight to edge
	# https://github.com/juju/charmstore-client/issues/146
	charm push $(CHARM_BUILD_DIR)/$(CHARM_NAME) cs:~$(CHARM_STORE_GROUP)/$(CHARM_NAME) > $(CHARM_PUSH_RESULT)
	cat $(CHARM_PUSH_RESULT)
	awk 'NR==1{print $$2}' $(CHARM_PUSH_RESULT) | xargs -I{} charm release {} --channel edge

clean: ## Remove .tox and build dirs
	rm -rf .tox/
	rm -rf build/
	rm -rf $(CHARM_PUSH_RESULT)

# Display target comments in 'make help'
help: 
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# SETTINGS
# Use one shell for all commands in a target recipe
.ONESHELL:
# Set default goal
.DEFAULT_GOAL := help
# Use bash shell in Make instead of sh 
SHELL := /bin/bash
