from dotenv import load_dotenv
import json
import os
import requests
import hashlib

from url_normalize import url_normalize

class CheckThreatFox:
    def __init__(self):
        load_dotenv()
        self.__api_key = os.getenv('THREATFOX_API_KEY')

    def __scan_url(self, url):
        # url = url_normalize(url) #TODO Normalize in main

        api_url = "https://threatfox-api.abuse.ch/api/v1/"

        final_results = {}
        final_results['ok'] = 1
        final_results['error'] = ''

        try:

            headers = {'Auth-Key': self.__api_key}
            payload = {'query': 'search_ioc', 'search_term': url, "exact_match": True}
            r = requests.post(api_url, json=payload, headers=headers, timeout=30)
            final_results['status_code'] = r.status_code
            content = r.json()
            if content['query_status'] != 'ok':
                final_results['ok'] = 0
                final_results['error'] = content['query_status']
                return final_results
            
            data = content['data'][0]

        except Exception as e:
            final_results['ok'] = 0
            final_results['error'] = e
            return final_results

        final_results['raw_response'] = data #TODO: each checker should store the raw response in filepath: /url/..
        final_results['url'] = data['ioc']
        final_results['threat_type'] = data['threat_type']
        final_results['malware_name'] = data['malware']
        
        final_results['type_desc'] = data['ioc_type_desc']
        return final_results

    def run(self, url: str, path: str = None) -> None:
        results = self.__scan_url(url)

        if path != None:
            file_name = f'threatfox_raw_output_{hashlib.md5(url.encode()).hexdigest()}.json'
            file_path = os.path.join(path, file_name)
            with open(file_path, 'w') as file:
                file.write(json.dumps(results))


    
if __name__ == '__main__':
    object = CheckThreatFox()
    print(object.run('https://salator.es/login/', './'))
