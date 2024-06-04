from requests_oauthlib import OAuth1Session

# Your credentials
consumer_key = '5f26443e0618399c4cac2cfcff77bae3fbb1aff81b1d4f5692dda299a43aaa50'
consumer_secret = '770fa7e6820ab904a305cddb4483980f495bb3707e13279c348acdc4b6594c9e'
token = '390cb55f8189738585143c0e5c42f3a3597265b7ececcb35fd2b715370aa12c5'
token_secret = '27bb0706f4ef86d9a3c141f063cfc0b1ea0d6720991b41c1417240e9097bb0a6'

# The URL for the NetSuite REST API endpoint for customers
url = 'https://4914352.app.netsuite.com/services/rest/record/v1/customer'

# Initialize the OAuth1 session with your NetSuite credentials
session = OAuth1Session(consumer_key, client_secret=consumer_secret,
                        resource_owner_key=token, resource_owner_secret=token_secret,
                        signature_method='HMAC-SHA256')

# Set the necessary headers. NetSuite APIs typically require specifying the content type and possibly other headers.
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

# Perform the GET request to retrieve customer data
response = session.get(url, headers=headers)

# Check if the request was successful
if response.status_code == 200:
    # Print the retrieved customer data
    print("Customer List Retrieved Successfully:")
    print(response.json())  # Assuming the response is in JSON format
else:
    print("Failed to retrieve customer list. Status code:", response.status_code)
    print(response.text)
