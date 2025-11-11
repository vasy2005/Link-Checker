import requests
from dotenv import load_dotenv
import json
import os
import hashlib

from url_normalize import url_normalize

class CheckGoogleSB:
    def __init__(self):
        load_dotenv()
        self.__api_key = os.getenv('GOOGLESB_API_KEY')

    def __scan_url(self, url):
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

        final_results = {}
        final_results['ok'] = 1
        final_results['error'] = ''

        body = {
            "client":
                {
                    "clientId": "Link-Checker",
                    "clientVersion": "1.0"
                },
            "threatInfo":
                {
                    'threatTypes':
                     [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{'url': url}]
                }
                }

        try:
            params = {'key': self.__api_key}
            response = requests.post(api_url, params=params, json=body, timeout=10)

            final_results['status_code'] = response.status_code
            
            if response.status_code != 200:
                final_results['ok'] = 0
                final_results['error'] = response.text
                return final_results

        except Exception as e:
            final_results['ok'] = 0
            final_results['error'] = str(e)
            return final_results
        
        try:
            result = response.json()
            if 'matches' in result:
                match = result['matches'][0]
                final_results['threat_type'] = match['threatType']
                final_results['url'] = match['threat']['url']
                final_results['raw_response'] = match
            else:
                final_results['ok'] = 0
                final_results['error'] = 'No malware found'
            return final_results
        except Exception as e:
            final_results['ok'] = 0
            final_results['error'] = str(e)
            return final_results
    
    def run(self, url: str, path: str = None):
        results = self.__scan_url(url)

        if path != None:
            file_name = f'googlesb_raw_output_{hashlib.md5(url.encode()).hexdigest()}.json'
            file_path = os.path.join(path, file_name)
            with open(file_path, 'w') as file:
                file.write(json.dumps(results))

        return results


    
if __name__ == '__main__':
    object = CheckGoogleSB()
    print(object.run('https://salator.es/login/', './'))

