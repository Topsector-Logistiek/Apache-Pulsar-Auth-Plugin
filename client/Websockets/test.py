import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import unittest

import websockets

from updateToken import updateToken

async def test_websocket_connection(url, token, namespace, topicName, subscriptionName = 'Apache_Pulsar_Consumer_VM_subscription_Websocket-TEST', role = 'consumer', delegation = None):
    uri = "wss://{_url}/ws/v2/{_role}/persistent/public/{_namespace}/{_topic}/{_subscriptionName}".format(_url = url, _namespace = namespace, _topic = topicName, _role=role, _subscriptionName = subscriptionName)
    headers = {"Authorization": f"Bearer {token}"}
    if delegation:
        headers["Delegation-trail"] = delegation
    
    async with websockets.connect(uri, extra_headers=headers) as websocket:
        if websocket.open:
            return True
    return False

class Test(unittest.IsolatedAsyncioTestCase):
    client_id = "EU.EORI.NLSECURESTO"
    client_private_key_file = "EU.EORI.NLSECURESTOpriv.pem"
    client_x5c_file = "EU.EORI.NLSECURESTO_x5c.txt"
    client2_id = "EU.EORI.NLSMARTPHON"
    client2_private_key_file = "EU.EORI.NLSMARTPHONpriv.pem"
    client2_x5c_file = "EU.EORI.NLSMARTPHON_x5c.txt"

    broker_provider_id = "EU.EORI.NL809023854"
    
    url = "pulsar.westeurope.cloudapp.azure.com"
    topicName  = 'topsector'
    namespace = "EU.EORI.NL809023854"
    subscriptionName = 'Apache_Pulsar_Consumer_VM_subscription_Websocket-test' #Zelf te kiezen naam - uniek per client
    access_token = ""

    async def test_broker_signed_access_token(self):        
        jwt_token = updateToken(self.broker_provider_id, self.client_id, self.client_private_key_file, self.client_x5c_file)
        self.__class__.access_token = jwt_token

        self.assertTrue(await test_websocket_connection(self.url, jwt_token, self.namespace, self.topicName, self.subscriptionName))

    async def test_self_signed_access_token(self):
        #Create a self signed access token
        current_time = int(time.time())
        expiration_time = current_time + 864000
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        headers = jwt.get_unverified_header(self.access_token)

        decoded_claims = jwt.decode(self.access_token, options={"verify_signature": False})
        claims = {
            "sub":  decoded_claims["sub"],
            "jti": decoded_claims["jti"],
            "nbf": current_time,
            "exp": expiration_time,
            "iat": current_time,
            "iss": decoded_claims["iss"],
            "aud": decoded_claims["aud"]
        }
        jwt_token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')

        with self.assertRaises((TimeoutError, websockets.exceptions.InvalidStatusCode)):
            await test_websocket_connection(self.url, jwt_token, self.namespace, self.topicName, self.subscriptionName)

    ## EU.EORI.NLSECURESTO has the permission registered in the AR of EU.EORI.NL809023854 to subscribe to topic 'topsector' in the namespace 'EU.EORI.NL809023854'
    async def test_subscribe_EORI_present_in_AR(self):        
        jwt_token = updateToken(self.broker_provider_id, self.client_id, self.client_private_key_file, self.client_x5c_file)
        self.__class__.access_token = jwt_token

        self.assertTrue(await test_websocket_connection(self.url, jwt_token, self.namespace, self.topicName, self.subscriptionName))

    ## EU.EORI.NLSECURESTO does NOT have a permission registered in the AR of EU.EORI.NL809023854 to publish to topic 'topsector' in the namespace 'EU.EORI.NL809023854'
    async def test_publish_EORI_not_present_in_AR(self):        
        jwt_token = updateToken(self.broker_provider_id, self.client_id, self.client_private_key_file, self.client_x5c_file)
        self.__class__.access_token = jwt_token

        with self.assertRaises((TimeoutError, websockets.exceptions.InvalidStatusCode)):
            await test_websocket_connection(self.url, jwt_token, self.namespace, self.topicName, self.subscriptionName, "producer")

    ## EU.EORI.NL809023854 has the permission registered in the AR of EU.EORI.NL809023854 to subscribe to topic 'topsector' in the namespace 'EU.EORI.NL809023854'
    ## EU.EORI.NLSMARTPHON has the permission registered in the AR of EU.EORI.NL809023854 to subscribe to topic 'topsector' in the namespace 'EU.EORI.NL809023854'
    async def test_subscribe_delegation_EORI_present_in_AR(self):
        jwt_token = updateToken(self.broker_provider_id, self.client2_id, self.client2_private_key_file, self.client2_x5c_file)
        self.__class__.access_token = jwt_token

        self.assertTrue(await test_websocket_connection(self.url, jwt_token, self.namespace, self.topicName, self.subscriptionName, delegation="EU.EORI.NL809023854"))

    async def test_publish_delegation_EORI_not_present_in_AR(self):
        jwt_token = updateToken(self.broker_provider_id, self.client2_id, self.client2_private_key_file, self.client2_x5c_file)
        self.__class__.access_token = jwt_token

        with self.assertRaises((TimeoutError, websockets.exceptions.InvalidStatusCode)):
            await test_websocket_connection(self.url, jwt_token, self.namespace, self.topicName, self.subscriptionName, role="producer", delegation="EU.EORI.NL809023854")


if __name__ == "__main__":
    unittest.main()