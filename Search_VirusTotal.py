# API Documentation: https://developers.virustotal.com/v3.0/reference#overview
# To sign up for a VirusTotal API key: https://www.virustotal.com/gui/join-us

# test data
# malicious url: https://poradu.com.ua/daadsadsa/Drive
# malicuous file hash: 316F09B531729502D05EBCF6A2B02B27
# malicious ip address: 31.131.21.89

import requests
import json
import base64
import sys

vt_api_key = '<VIRUSTOTAL API KEY>'

def virustotal_url_query(url_to_query = '', api_key = ''):
    """
    
    This function queries Virustotal for a given URL and returns information about the URL.
    Supporting Documentation: https://developers.virustotal.com/v3.0/reference#url-info

    """
    def encode_base64(data_to_encode):
        data_to_encode_bytes = data_to_encode.encode('ascii')
        encoded_bytes = base64.b64encode(data_to_encode_bytes)
        encoded_string = str(encoded_bytes.decode('ascii'))
        return encoded_string.replace('=','') # the virustotal api endpoint needs the base64 padding omitted
        
    api_base = 'https://www.virustotal.com/api/v3/urls/'
    api_endpoint = encode_base64(url_to_query)
    query_url = api_base + api_endpoint
    headers = {
            'Accept': 'application/json',
            'x-apikey': api_key
        }
    response = requests.request(method='GET', url=query_url, headers=headers, verify=False) # 'verify' param is set to false to prevent any ssl issues while on VPN. Def a hack but it works :)
    decodedResponse = json.loads(response.text)
    print(decodedResponse)

def virustotal_filehash_query(file_hash = '', api_key = ''):
    """

    This function queries for a given file hash and returns information about that file.
    The function accepts SHA-256, SHA-1 or MD5 file hashes. 
    Supporting Documentation: https://developers.virustotal.com/v3.0/reference#file-info
    
    """
    api_base = 'https://www.virustotal.com/api/v3/files/'
    api_endpoint = file_hash
    query_url = api_base + api_endpoint
    headers = {
            'Accept': 'application/json',
            'x-apikey': api_key
        }
    response = requests.request(method='GET', url=query_url, headers=headers, verify=False) # 'verify' param is set to false to prevent any ssl issues while on VPN. Def a hack but it works :)
    decodedResponse = json.loads(response.text)
    print(decodedResponse)

def virustotal_ipaddress_query(ip = '', api_key = ''):
    """

    This function queries for a given IP address and returns information about the IP address. 
    Supporting Documentation: https://developers.virustotal.com/v3.0/reference#ip-info

    """
    api_base = 'https://www.virustotal.com/api/v3/ip_addresses/'
    api_endpoint = ip
    query_url = api_base + api_endpoint
    headers = {
            'Accept': 'application/json',
            'x-apikey': api_key
        }
    response = requests.request(method='GET', url=query_url, headers=headers, verify=False) # 'verify' param is set to false to prevent any ssl issues while on VPN. Def a hack but it works :)
    decodedResponse = json.loads(response.text)
    print(decodedResponse)

if len(sys.argv) > 1:
    if sys.argv[1] == '--url':
        virustotal_url_query(sys.argv[2], vt_api_key)
    elif sys.argv[1] == '--file':
        virustotal_filehash_query(sys.argv[2], vt_api_key)
    elif sys.argv[1] == '--ip':
        virustotal_ipaddress_query(sys.argv[2], vt_api_key)
else:
    print("""
    Script Usage: 
    --url   url to query
    --file  file hash to query
            accepts a SHA-256, SHA-1, or MD5 hash
    --ip    ip address to query
    """)
