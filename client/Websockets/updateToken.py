import time
import uuid
import requests
import json
import jwt


def updateToken(aud, iss, private_key_file, x5c_file):
  with open(private_key_file, "r") as file:
    private_key = file.read()

  with open(x5c_file, "r") as file:
    x5c_header = file.read()

  current_time = int(time.time())
  expiration_time = current_time + 30
  headers = {
      "x5c": [x5c_header],
      "typ": "JWT"
  }
  claims = {
      "sub": iss,
      "jti": str(uuid.uuid4()),
      "nbf": current_time,
      "exp": expiration_time,
      "iat": current_time,
      "iss": iss,
      "aud": aud
  }
  clientAssertion = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')

  url_access_token = "https://ishare-common-container-app.orangebush-8d078598.westeurope.azurecontainerapps.io/connect/Token"
  
  payload_access_token = (
    "grant_type=client_credentials&scope=iSHARE&"
    "client_id={_clientId}&"
    "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&"
    "client_assertion={_clientAssertions}").format(_clientId = iss, _clientAssertions = clientAssertion)
  headers_access_token = {
    'Content-Type': 'application/x-www-form-urlencoded'
  }

  response_access_token = requests.request("POST", url_access_token, headers=headers_access_token, data=payload_access_token)

  access_token = json.loads(response_access_token.text)
  accessToken = access_token['access_token']
  return accessToken

if __name__ == "__main__":
  aud = "EU.EORI.NL809023854"
  iss = "EU.EORI.NLSECURESTO"
  private_key_file = "EU.EORI.NLSECURESTOpriv.pem"
  x5c_header_file = "EU.EORI.NLSECURESTO_x5c.txt"
  print(updateToken(aud, iss, private_key_file, x5c_header_file))
