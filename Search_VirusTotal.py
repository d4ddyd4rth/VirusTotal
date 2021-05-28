# API Documentation: https://developers.virustotal.com/v3.0/reference#overview
# To sign up for a VirusTotal API key: https://www.virustotal.com/gui/join-us

# test data
# malicious url: https://poradu.com.ua/daadsadsa/Drive
# malicuous file hash: 316F09B531729502D05EBCF6A2B02B27
# malicious ip address: 54.225.144.221

import requests
import json
import base64
import sys
from datetime import datetime, timezone

vt_api_key = 'VIRUSTOTAL API KEY'

def print_moosey():
    print("""
                                       /) \ |\    //
                                 (\|  || \)u|   |F     /)
                                  \```.FF  \  \  |J   .'/
                               __  `.  `|   \  `-'J .'.'
        ______           __.--'  `-. \_ J    >.   `'.'   .
    _.-'      ""`-------'           `-.`.`. / )>.  /.' .<'
  .'                                   `-._>--' )\ `--''
  F .                                          ('.--'"
 (_/            VirusTotal Search                '
  \                                             'o`.
  |\                                                `.
  J \          |              /      |                |
   L \                       J       (             .  |
   J  \      .               F        _.--'`._  /`. \_)
    F  `.    |                       /        ""   "'
    F   /\   |_          ___|   `-_.'
   /   /  F  J `--.___.-'   F  - /
  /    F  |   L            J    /|
 (_   F   |   L            F  .'||
  L  F    |   |           |  /J  |
  | J     `.  |           | J  | |              ____.---.__
  |_|______ \  L          | F__|_|___.---------'
--'        `-`--`--.___.-'-'---
    """)


def virustotal_url_query(url_to_query = '', api_key = ''):
    """
    
    This function queries Virustotal for a given URL and returns information about the URL.
    Supporting Documentation: https://developers.virustotal.com/v3.0/reference#url-info

    """
    print_moosey()

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
    response = requests.request(method='GET', url=query_url, headers=headers)
    decodedResponse = json.loads(response.text)

    last_ip_response = requests.request(method='GET', url=query_url + '/last_serving_ip_address', headers=headers)
    decoded_last_ip_reponse = json.loads(last_ip_response.text)

    # everything below this line is just a report of the search results and everything above the actual logic to query the api

    print('')
    print("VirusTotal URL Search Results for: ")
    print(url_to_query)
    print('')
    print("VirusTotal Link: ")
    print(" https://www.virustotal.com/gui/url/"+ str(decodedResponse['data']['id']) + "/detection")
    print('First Submission Date: ' + str(datetime.fromtimestamp(decodedResponse['data']['attributes']['last_submission_date'], tz=timezone.utc)) + ' UTC')
    print('Last Analysis Date: ' + str(datetime.fromtimestamp(decodedResponse['data']['attributes']['last_submission_date'], tz=timezone.utc)) + ' UTC')
    print('Serving IP Address: ' + str(decoded_last_ip_reponse['data']['id']) + '\n')
    print('')
    print('Reputation Scores:')
    print(" Harmless: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['harmless']))
    print(" Malicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['malicious']))
    print(" Suspicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['suspicious']))
    print(" Undetected: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['undetected']) + '\n')
    print('')
    print('Detection Engine Results:')
    for i in decodedResponse['data']['attributes']['last_analysis_results']:
        if decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'harmless' or decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'undetected':
            continue
        else:
            print(' Engine: ' + i)
            print(' Verdict: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['category']))
            print(' Reasoning: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['result']) + '\n')

def virustotal_filehash_query(file_hash = '', api_key = ''):
    """

    This function queries for a given file hash and returns information about that file.
    The function accepts SHA-256, SHA-1 or MD5 file hashes. 
    Supporting Documentation: https://developers.virustotal.com/v3.0/reference#file-info
    
    """
    print_moosey()

    api_base = 'https://www.virustotal.com/api/v3/files/'
    api_endpoint = file_hash
    query_url = api_base + api_endpoint
    headers = {
            'Accept': 'application/json',
            'x-apikey': api_key
        }
    response = requests.request(method='GET', url=query_url, headers=headers)
    decodedResponse = json.loads(response.text)

    contacted_url_response = requests.request(method='GET', url=query_url + '/contacted_urls', headers=headers)
    decoded_contacted_url_response = json.loads(contacted_url_response.text)

    # everything below this line is just a report of the search results and everything above the actual logic to query the api
    print('')
    print("VirusTotal URL Search Results for: ")
    print(file_hash)
    print('')
    print("VirusTotal Link: ")
    print(" https://www.virustotal.com/gui/file/"+ str(decodedResponse['data']['id']) + "/detection")
    print("File Name(s): ")
    for i in decodedResponse['data']['attributes']['names']:
        print(' ' + i)
    print('First Submission Date: ' + str(datetime.fromtimestamp(decodedResponse['data']['attributes']['last_submission_date'], tz=timezone.utc)) + ' UTC')
    print('Last Analysis Date: ' + str(datetime.fromtimestamp(decodedResponse['data']['attributes']['last_submission_date'], tz=timezone.utc)) + ' UTC')
    print("Number of Submissions: " + str(decodedResponse['data']['attributes']['times_submitted']))
    print("File Type: " + str(decodedResponse['data']['attributes']['type_description']))
    print('File Creation Date: ' + str(datetime.fromtimestamp(decodedResponse['data']['attributes']['creation_date'], tz=timezone.utc)) + ' UTC')
    print("SHA-256: " + str(decodedResponse['data']['attributes']['sha256']))
    print("SHA-1: " + str(decodedResponse['data']['attributes']['sha1']))
    print("MD5: " + str(decodedResponse['data']['attributes']['md5']))
    print('')
    print('Reputation Scores:')
    print(" Malicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['malicious']))
    print(" Suspicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['suspicious']))
    print(" Undetected: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['undetected']))
    print(" Harmless: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['harmless']))
    print(" Type Unspported: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['type-unsupported']))
    print('')
    print('File Contacts the Following URLs:')
    for i in decoded_contacted_url_response['data']:
        print(' ' + i['attributes']['url'])
    print('')
    print('Detection Engine Results:')
    for i in decodedResponse['data']['attributes']['last_analysis_results']:
        if decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'harmless' or decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'undetected' or decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'type-unsupported':
            continue
        else:
            print(' Engine: ' + i)
            print(' Verdict: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['category']))
            print(' Reasoning: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['result']) + '\n')


def virustotal_ipaddress_query(ip = '', api_key = ''):
    """

    This function queries for a given IP address and returns information about the IP address. 
    Supporting Documentation: https://developers.virustotal.com/v3.0/reference#ip-info

    """
    print_moosey()

    api_base = 'https://www.virustotal.com/api/v3/ip_addresses/'
    api_endpoint = ip
    query_url = api_base + api_endpoint
    headers = {
            'Accept': 'application/json',
            'x-apikey': api_key
        }
    response = requests.request(method='GET', url=query_url, headers=headers)
    decodedResponse = json.loads(response.text)

    # everything below this line is just a report of the search results and everything above the actual logic to query the api
    print('')
    print("VirusTotal IP Search Results for: ")
    print(ip)
    print('')
    print("VirusTotal Link: ")
    print(" https://www.virustotal.com/gui/ip-address/"+ str(decodedResponse['data']['id']) + "/detection")
    print("Subnet: " + str(decodedResponse['data']['attributes']['network']))
    print("Regional Internet Registry: " + str(decodedResponse['data']['attributes']['regional_internet_registry']))
    print("Country: " + str(decodedResponse['data']['attributes']['country']))
    print("Continent: " + str(decodedResponse['data']['attributes']['continent']))
    print("Owner: " + str(decodedResponse['data']['attributes']['as_owner']))
    print('')
    print('Reputation Scores:')
    print(" Malicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['malicious']))
    print(" Suspicious: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['suspicious']))
    print(" Undetected: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['undetected']))
    print(" Harmless: " + str(decodedResponse['data']['attributes']['last_analysis_stats']['harmless']))
    print('')
    print('Detection Engine Results:')
    for i in decodedResponse['data']['attributes']['last_analysis_results']:
        if decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'harmless' or decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'undetected' or decodedResponse['data']['attributes']['last_analysis_results'][i]['category'] == 'type-unsupported':
            continue
        else:
            print(' Engine: ' + i)
            print(' Verdict: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['category']))
            print(' Reasoning: ' + str(decodedResponse['data']['attributes']['last_analysis_results'][i]['result']))
    print('')
    print("Whois Information: ")
    print(str(decodedResponse['data']['attributes']['whois']))
    
if len(sys.argv) > 1:
    if sys.argv[1] == '--url':
        virustotal_url_query(sys.argv[2], vt_api_key)
    elif sys.argv[1] == '--file':
        virustotal_filehash_query(sys.argv[2], vt_api_key)
    elif sys.argv[1] == '--ip':
        virustotal_ipaddress_query(sys.argv[2], vt_api_key)
else:
    print_moosey()
    print("""
    Script Usage: 
    --url   url to query
    --ip    ip address to query
    --file  file hash to query
            accepts a SHA-256, SHA-1, or MD5 hash
    """)
