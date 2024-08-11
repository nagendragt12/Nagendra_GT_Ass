import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

# HubSpot OAuth2 client credentials
CLIENT_ID = '53c92ca4-71a7-41c5-8374-f77b80b1fe94'
CLIENT_SECRET = '9c0f7af3-15ec-4ced-becf-dca0ae1d86b4'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'

# Authorization URL for HubSpot OAuth2
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code'

# Specify the required scopes
scope = 'oauth'  

# Encode client ID and secret for Basic Authentication
encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

async def authorize_hubspot(user_id, org_id):
    # Create state data to prevent CSRF attacks
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    # Encode the state data and store it in Redis with a 10-minute expiration
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)

    # Include the scope in the authorization URL
    return f'{authorization_url}&state={encoded_state}&scope={scope}'

async def oauth2callback_hubspot(request: Request):
    # Log the incoming request parameters for debugging
    print("Request query params:", request.query_params)

    # Check for errors in the callback
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    
    # Extract code and state from the query parameters
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')
   

    # Retrieve the saved state from Redis
    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}') 

    # Validate the state to prevent CSRF attacks
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    # Exchange the authorization code for an access token
    async with httpx.AsyncClient() as client:
        response = await client.post(
            'https://api.hubapi.com/oauth/v1/token',
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT_URI,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
            },
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        )

    # Check if the token request was successful
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    # Store the retrieved credentials in Redis with a 10-minute expiration
    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', response.text, expire=600)
    # Return a script to close the authorization window
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    # Fetch the credentials from Redis
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    
    # Parse the credentials and delete them from Redis
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

# Create an IntegrationItem object from the HubSpot response
def create_integration_item_metadata_object(response_json) -> IntegrationItem:
    return IntegrationItem(
        id=response_json.get('id'),  
        name=response_json.get('properties', {}).get('name', 'Unnamed'),  
        type='HubSpot Object',  
        parent_id=None,  
        creation_time=response_json.get('createdAt'),  
        last_modified_time=response_json.get('updatedAt'),  
    )

async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    # Parse the credentials
    credentials = json.loads(credentials)  
    access_token = credentials.get('access_token') 
    # Example endpoint for contacts 
    url = 'https://api.hubapi.com/crm/v3/objects/contacts'  
    # List to store metadata
    list_of_integration_item_metadata = []  

    # Fetch items from HubSpot
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers={'Authorization': f'Bearer {access_token}'})

    # Check if the request was successful
    if response.status_code == 200:
        # Get the results from the response
        results = response.json().get('results', [])  
        for result in results:
            # Create metadata objects for each result
            list_of_integration_item_metadata.append(create_integration_item_metadata_object(result))
    # Return the list of metadata objects
    return list_of_integration_item_metadata  