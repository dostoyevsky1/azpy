import logging
from azure.identity import DefaultAzureCredential
from msrest.authentication import BasicTokenAuthentication
from azure.core.pipeline.policies import BearerTokenCredentialPolicy
from azure.core.pipeline import PipelineRequest, PipelineContext
from azure.core.pipeline.transport import HttpRequest

from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient, ContainerClient, BlobClient

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.cosmos import CosmosClient

logging.Logger.root.level = 10
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)

SUB = '14e538ca-8240-498c-b0b9-5e9a6eafe2c7'

class CredentialWrapper(BasicTokenAuthentication):
    def __init__(self, credential=None, resource_id="https://management.azure.com/.default", **kwargs):
        """Wrap any azure-identity credential to work with SDK that needs azure.common.credentials/msrestazure.

        Default resource is ARM (syntax of endpoint v2)

        :param credential: Any azure-identity credential (DefaultAzureCredential by default)
        :param str resource_id: The scope to use to get the token (default ARM)
        """
        super(CredentialWrapper, self).__init__(None)
        if credential is None:
            credential = DefaultAzureCredential()
        self._policy = BearerTokenCredentialPolicy(credential, resource_id, **kwargs)

    def _make_request(self):
        return PipelineRequest(
            HttpRequest(
                "CredentialWrapper",
                "https://fakeurl"
            ),
            PipelineContext(None)
        )

    def set_token(self):
        """Ask the azure-core BearerTokenCredentialPolicy policy to get a token.

        Using the policy gives us for free the caching system of azure-core.
        We could make this code simpler by using private method, but by definition
        I can't assure they will be there forever, so mocking a fake call to the policy
        to extract the token, using 100% public API."""
        request = self._make_request()
        self._policy.on_request(request)
        # Read Authorization, and get the second part after Bearer
        token = request.http_request.headers["Authorization"].split(" ", 1)[1]
        self.token = {"access_token": token}

    def signed_session(self, session=None):
        self.set_token()
        return super(CredentialWrapper, self).signed_session(session)

class AzureHelper:
    def __init__(self):
        pass

    def generate_mgmt_credentials(self):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: generating Azure Management plane credentials via Credential Wrapper for azure identity')
        try:
            self._mgmt_credentials = CredentialWrapper()
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')

    def generate_data_credentials(self):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: generating Azure Data plane credentials via Default Credentials for azure identity')
        try:
            self._data_credentials = DefaultAzureCredential()
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

    def get_storage_mgmt_client(self, subscription: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring storage resource management client connection')
        if subscription:
            self._subscription = subscription
        try:
            self._storage_mgmt_client = StorageManagementClient(self._mgmt_credentials, self._subscription)
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

        return self._storage_mgmt_client

    def get_resource_mgmt_client(self, subscription: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring storage resource management client connection')
        if subscription:
            self._subscription = subscription
        try:
            self._resource_mgmt_client = ResourceManagementClient(self._mgmt_credentials, self._subscription)
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

        return self._resource_mgmt_client

    def get_cosmosdb_mgmt_client(self, subscription: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring storage resource management client connection')
        if subscription:
            self._subscription = subscription
        try:
            self._cosmosdb_mgmt_client = CosmosDBManagementClient(self._mgmt_credentials, self._subscription)
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

        return self._cosmosdb_mgmt_client

    def get_storage_account_keys(self, resource_group: str, storage_account: str, storage_mgmt_client: object = None):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring storage account keys')
        if storage_mgmt_client:
            self._storage_mgmt_client = storage_mgmt_client
        try:
            self._storage_account_keys = self._storage_mgmt_client.storage_accounts.list_keys(resource_group,storage_account).keys
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

        return self._storage_account_keys
 
    def get_cosmosdb_account_keys(self, resource_group_name: str, cosmosdb_account_name: str, cosmosdb_mgmt_client: object = None):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: Acquiring Cosmos account keys')
        if not self._cosmosdb_mgmt_client:
            self._cosmosdb_mgmt_client = cosmosdb_mgmt_client
        try:
            self._cosmosdb_account_keys = cosmosdb_mgmt_client.database_accounts.list_keys(resource_group_name, cosmosdb_account_name)
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred: {e}')
            raise e

        return self._cosmosdb_account_keys

    def generate_storage_conn_string(self, storage_key: str, storage_account: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring storage account keys')
        try:
            self._storage_conn_string = f'DefaultEndpointsProtocol=https;AccountName={storage_account};AccountKey={storage_key};EndpointSuffix=core.windows.net'
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

        return self._storage_conn_string

    def get_storage_client(self, storage_conn_string: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring storage resource client connection')
        if storage_conn_string:
            self.storage_conn_string = storage_conn_string
        try:
            self._storage_client = BlobServiceClient.from_connection_string(self.storage_conn_string, self._data_credentials)
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

        return self._storage_client

    def get_cosmos_client(self, cosmos_url: str, cosmos_key: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring Cosmos client connection')
        try:
            self._cosmos_client = CosmosClient(cosmos_url, cosmos_key)
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred: {e}')
            raise e

        return self._cosmos_client
    
    def get_container_client(self, container_name: str, storage_client: object = None):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring container client connection')
        if storage_client:
            self._storage_client = storage_client
        try:
            self._container_client = self._storage_client.get_container_client(container_name)
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred {e}')
            raise e

        return self._container_client

    def get_api_versions(self, resource_id: str, resource_mgmt_client: object = None):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: acquiring API version')
        if resource_mgmt_client:
            self._resource_mgmt_client = resource_mgmt_client
        try:
            namespace = self.get_provider_namespace
            service = self.get_service_name
            provider = self._resource_mgmt_client.providers.get(namespace)
            resource_types = next((item for item in provider.resource_types if item.resource_type == service))
            api = resource_types.api_versions
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred: {e}')
            raise e

        return api
        
    def get_resource_group_name(self, resource_id: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: Acquiring resource group name')
        try:
            id_list = resource_id.lower().split('/')
            resource_group_name_idx = id_list.index('resourcegroups')+1
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred: {e}')
            raise e

        return resource_id.split('/')[resource_group_name_idx]

    def get_provider_namespace(self, resource_id: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: Acquiring resource/account name')
        try:
            id_list = resource_id.lower().split('/')
            provider_namespace_idx = id_list.index('providers')+1
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred: {e}')
            raise e

        return resource_id.split('/')[provider_namespace_idx]

    def get_service_name(self, resource_id: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: Acquiring resource/account name')
        try:
            id_list = resource_id.lower().split('/')
            service_name_idx = id_list.index('providers')+2
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred: {e}')
            raise e

        return resource_id.split('/')[service_name_idx]

    def get_resource_name(self, resource_id: str):
        logger = logging.getLogger(__name__)
        logger.info('LOGGER: Acquiring resource/account name')
        try:
            id_list = resource_id.lower().split('/')
            resource_name_idx = id_list.index('providers')+3
        except Exception as e:
            logger.error(f'LOGGER: Exception occurred: {e}')
            raise e

        return resource_id.split('/')[resource_name_idx]

    def get_cosmosdb_throughputs(self, cosmos_client: object = None):
        logger = logging.getLogger(__name__)
        if cosmos_client:
            self._cosmos_client = cosmos_client
        existing_dbs = [item['id'] for item in self._cosmos_client.list_databases()]
        db_dict = {}
        for db in existing_dbs:
            try:
                logger.info('LOGGER: Acquiring Cosmos database-level throughput')
                db_client = cosmos_client.get_database_client(db)
                try:
                    db_throughput = db_client.read_offer().properties['content']['offerThroughput']
                except Exception as e:
                    logger.error(f'LOGGER: Exception occurred: {e}')
                    logger.info('LOGGER: No database throughput option detected. Setting at none')
                    db_throughput = 'N/A'    
                existing_containers = [item['id'] for item in db_client.list_containers()]
            except Exception as e:
                logger.error(f'LOGGER: Exception occurred: {e}')
            finally:
                container_dict = {}
                if existing_containers:
                    for container in existing_containers:
                        try:
                            logger.info('LOGGER: Acquiring Cosmos container-level throughput')
                            container_throughput = db_client.get_container_client(container).read_offer().properties['content']['offerThroughput'] 
                            container_dict[container] = container_dict.get(container, container_throughput)
                        except Exception as e:
                            logger.error(f'LOGGER: Exception occurred: {e}')
                    db_dict[db] = {'containers': container_dict, 'throughput': db_throughput}
                else:
                    db_dict[db] = {'containers': container_dict, 'throughput': db_throughput}
        
        return db_dict

def init(SUB):
    AZ = AzureHelper()
    AZ.generate_data_credentials()
    AZ.generate_mgmt_credentials()
    AZ.get_resource_mgmt_client(SUB)
    AZ.get_cosmosdb_mgmt_client(SUB)
    
    return AZ