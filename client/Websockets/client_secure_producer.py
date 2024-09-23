#!/usr/bin/env python

import asyncio
import base64
import json
import websockets
import socket
from updateToken import updateToken


async def connect(url, header, namespace, topicName, subscriptionName, client_id, client_private_key_file, client_x5c_file, broker_provider_id):
    uri = "wss://{_url}/ws/v2/producer/persistent/public/{_namespace}/{_topic}".format(_url = url, _namespace = namespace, _topic = topicName)
    
    async with websockets.connect(uri, extra_headers=header) as websocket:
        while websocket.open:
            receive_task = asyncio.create_task(receive(websocket, broker_provider_id, client_id, client_private_key_file, client_x5c_file))
            await receive_task

            send_task = asyncio.create_task(send(websocket))
            await send_task

async def send(websocket):
    payloadString = "Sample Message" 

    payloadString = payloadString.encode('utf-8')
    payloadString = base64.b64encode(payloadString)
    payloadString = payloadString.decode('UTF-8')


    pulsarMessageFormat = json.dumps({
        'payload' : payloadString
    })

    print('Send message:', pulsarMessageFormat)

    await websocket.send(pulsarMessageFormat)

    #Wait 5 seconds before sending the message again
    await asyncio.sleep(5)

async def receive(websocket, broker_provider_id, client_id, client_private_key_file, client_x5c_file):
    try:
        message = await asyncio.wait_for(websocket.recv(), timeout=0.1)
        print("Message received:", message)

        msg = json.loads(message)      
        if 'type' in msg and msg['type']=='AUTH_CHALLENGE':
            tokenN = updateToken(broker_provider_id, client_id, client_private_key_file, client_x5c_file)
            jsondump = json.dumps({'type' : 'AUTH_RESPONSE', 'authResponse' : {'clientVersion' : 'v21', 'protocolVersion' : 21, 'response' : {'authMethodName':'token', 'authData': tokenN}}})
            print('Send messgae:', jsondump)
            await websocket.send(jsondump)
        elif 'result' in msg and msg['result'] == 'ok':
                print('.', end='')
        else:
            print('Failed to publish message:', message)
        
    except asyncio.TimeoutError:
        print("No Data")
    await asyncio.sleep(0.1)

if __name__ == "__main__":

    client_id = "EU.EORI.NLSECURESTO"
    client_private_key_file = "EU.EORI.NLSECURESTOpriv.pem"
    client_x5c_file = "EU.EORI.NLSECURESTO_x5c.txt"
    broker_provider_id = "EU.EORI.NL809023854"
    
    token = updateToken(broker_provider_id, client_id, client_private_key_file, client_x5c_file)

    broker_url = "pulsar.westeurope.cloudapp.azure.com"
    subscriptionName = 'Apache_Pulsar_Producer_VM_Websocket_' + socket.gethostname()
    topic_owner_id = "EU.EORI.NL809023854"
    topic_name  = 'topsector'   
    
    header = {
            "Authorization": f"Bearer {token}", 
            "Delegation-trail":"EU.EORI.NL809023854"
        }

    asyncio.run(connect(broker_url, header, topic_owner_id, topic_name, subscriptionName, client_id, client_private_key_file, client_x5c_file, broker_provider_id))