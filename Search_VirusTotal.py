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
from datetime import datetime, timezone

vt_api_key = '58d7e80944c9f7dca5cc78abba84f43aa1bd7cc0021f840c057764c7da60cbe3'

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

    # everything below this line is just a report of the search results and everything above the actual logic to query the api
    last_analysis_timestamp = int(decodedResponse['data']['attributes']['last_analysis_date'])
    first_submission_timestamp = int(decodedResponse['data']['attributes']['first_submission_date'])

    print("\n")
    print("VirusTotal URL Search Results for: ")
    print(url_to_query + '\n')
    print('First Submission Date: ' + str(datetime.fromtimestamp(first_submission_timestamp, tz=timezone.utc)) + ' UTC')
    print('Last Analysis Date: ' + str(datetime.fromtimestamp(last_analysis_timestamp, tz=timezone.utc)) + ' UTC')
    print("Harmless: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['harmless']))
    print("Malicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['malicious']))
    print("Suspicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['suspicious']))
    print("Undetected: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
    print('Detection Engine Results:')
    for i in decodedResponse['data']['attributes']['last_analysis_results']:
        if decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'harmless' or decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'undetected':
            continue
        else:
            print('Engine: ' + i)
            print('Category: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['category']))
            print('Reasoning: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['result']) + '\n')

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
