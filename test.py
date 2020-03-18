from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import requests, sys

CLIENT_ID = "01ff3f2f-c91c-4db8-abdc-2ea5bfcd57f9"
CLIENT_SECRET = sys.argv[1]

client = BackendApplicationClient(client_id=CLIENT_ID)
oauth = OAuth2Session(client=client)
token = oauth.fetch_token(token_url='https://login.microsoftonline.com/fe8041b2-2127-4652-9311-b420e55fd10e/oauth2/v2.0/token', client_id=CLIENT_ID, client_secret=CLIENT_SECRET, scope=["https://graph.microsoft.com/.default"])

HEADER = {"Content-Type": "application/json", "Authorization": "Bearer %s" % token.get("access_token")}

print(token.get("access_token"))
res = requests.get("https://graph.microsoft.com/v1.0/directoryObjects/fe8041b2-2127-4652-9311-b420e55fd10e", headers=HEADER)
