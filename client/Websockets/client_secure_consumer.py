#!/usr/bin/env python

import asyncio
import base64
import json
import websockets
import socket
from updateToken import updateToken

async def connectConsumer(url, header, namespace, topicName, subscriptionName, client_id, client_private_key_file, client_x5c_file, broker_provider_id):
    uri = "wss://{_url}/ws/v2/consumer/persistent/public/{_namespace}/{_topic}/{_subscriptionName}".format(_url = url, _namespace = namespace, _topic = topicName, _subscriptionName = subscriptionName)
    async with websockets.connect(uri, extra_headers=header) as websocket:
        while websocket.open:
            try:
                result = await websocket.recv()
                print( "Received msg: {}".format(result))

                msg = json.loads(result)
                if not msg:
                    break
                
                
                if 'type' in msg and msg['type']=='AUTH_CHALLENGE':
                    tokenN = updateToken(broker_provider_id, client_id, client_private_key_file, client_x5c_file)
                    jsondump = json.dumps({'type' : 'AUTH_RESPONSE', 'authResponse' : {'clientVersion' : 'v21', 'protocolVersion' : 21, 'response' : {'authMethodName':'token', 'authData': tokenN}}})

                    print('Send message:', jsondump)
                    await websocket.send(jsondump)
                else:
                    print( "Received msg: {}".format(base64.b64decode(msg['payload'])))
                    
                    # Send ack
                    await websocket.send(json.dumps({'messageId' : msg['messageId']}))

            except:
                print("Some error")


if __name__ == "__main__":
    client_id = "EU.EORI.NLSECURESTO"
    client_private_key_file = "EU.EORI.NLSECURESTOpriv.pem"
    client_x5c_file = "EU.EORI.NLSECURESTO_x5c.txt"

    broker_provider_id = "EU.EORI.NL809023854"
    
    token = updateToken(broker_provider_id, client_id, client_private_key_file, client_x5c_file)

    broker_url = "pulsar.westeurope.cloudapp.azure.com"
    topic_owner_id = "EU.EORI.NL809023854"
    topic_name  = 'topsector'
    
    subscriptionName = 'Apache_Pulsar_Consumer_VM_subscription_Websocket-' + socket.gethostname() #Zelf te kiezen naam - uniek per client

    header = {
                "Authorization": f"Bearer {token}", 
                "Delegation-trail":"EU.EORI.NL809023854"
            }
    
    asyncio.run(connectConsumer(broker_url, header, topic_owner_id, topic_name, subscriptionName, client_id, client_private_key_file, client_x5c_file, broker_provider_id))

    