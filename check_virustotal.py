import vt
from vt.object import WhistleBlowerDict
from vt.error import APIError
import os
import time
import json
import hashlib
import aiohttp

from dotenv import load_dotenv
from url_normalize import url_normalize

class CheckVirusTotal:
    def __init__(self):
        load_dotenv()
        self.__api_key = os.getenv('VIRUSTOTAL_API_KEY')
        print(self.__api_key)

    def __into_dict(self, object):
        if isinstance(object, WhistleBlowerDict) or isinstance(object, dict):
            result = {}
            object = dict(object)
            for key in object.keys():
                result[key] = self.__into_dict(object[key])
            return result
        
        if isinstance(object, list):
            result = []
            for item in object:
                result.append(self.__into_dict(item))
            return result
        
        return object
            

    def __scan_url(self, url):
        with vt.Client(self.__api_key) as client:
            final_results = {}
            final_results['ok'] = 1
            final_results['error'] = ''

            try:
                
                url_id = vt.url_id(url)
                url_object = client.get_object(f'/urls/{url_id}')

                if not hasattr(url_object, "last_http_response_code") or url_object.last_http_response_code is None:
                    raise APIError(404, 'URL not found')
                if url_object and url_object.last_analysis_date:
                    age_days = (time.time() - url_object.last_analysis_date.timestamp()) / (24*60*60)

                    if age_days > 7:
                        raise APIError(404, 'Recent URL analysis not found')
                    
                        
                client.close()
            except APIError:
                analysis_id = client.scan_url(url)
                while True:
                    result = client.get_object(f"/analyses/{analysis_id.id}")
                    if result.status == 'completed':
                        break
                    time.sleep(1)

                url_object = client.get_object(f'/urls/{url_id}')
                
                client.close()
            except Exception as e:
                final_results['ok'] = 0
                final_results['error'] = str(e)
                client.close()
                return self.__into_dict(final_results)

            try:
                final_results['engine_stats'] = url_object.get('last_analysis_stats', None) # How many engines found the link to be malicious/suspicious/undetected/harmless/timeout
                final_results['community_votes'] = url_object.get('total_votes', None)
                final_results['times_submitted'] = url_object.get('times_submitted', None)
                final_results['internal_trust_score'] = url_object.get('reputation', None)
                final_results['url'] = url
                final_results['last_final_url'] = url_object.get('last_final_url', None)
                final_results['categories'] = url_object.get('categories', None)
                final_results['tags'] = url_object.get('tags', None)

                final_results['detailed_engine_results'] = url_object.get('last_analysis_results', None)
                final_results['flagged_by'] = [engine for engine, data in final_results['detailed_engine_results'].items() if data['category'] == 'malicious']

                if final_results['engine_stats']['malicious'] > 3 or final_results['internal_trust_score'] < 0:
                    final_results['verdict'] = 'malware'
                else:
                    final_results['verdict'] = 'harmless'

                final_results['last_http_code'] = url_object.get('last_http_response_code', None)
                client.close()
                #TODO: check redirection_chain
                # reputation: > 1000 very good reputation, 0-1000 neutral, < 0 suspicious
                
                return self.__into_dict(final_results)
            except Exception as e:
                final_results['ok'] = 0
                final_results['error'] = str(e)
                client.close()
                return self.__into_dict(final_results)
    
    def __vt_report(self, results):
        output = f'URL: {results['url']}\n'
        output += f'{results['engine_stats']['malicious']}/98 security vendors flagged this URL as malicious\n'
        output += f'Summary of engine results:\n  Malicious: {results['engine_stats']['malicious']}/98\n  Suspicious: {results['engine_stats']['suspicious']}/98\n  Undetected: {results['engine_stats']['undetected']}/98\n  Harmless: {results['engine_stats']['harmless']}/98\n'
        output += f'Community votes:\n  Harmless: {results['community_votes']['harmless']}\n  Malicious: {results['community_votes']['harmless']}\n'
        output += f'VirusTotal internal trust score: {results['internal_trust_score']}, '
        if (results['internal_trust_score'] >= 1000):
            output += f'very good reputation'
        elif results['internal_trust_score'] >= 0:
            output += f'neutral reputation'
        else:
            output += f'suspicious reputation'
        output += '\n' 
        output += f'Verdict: {results['verdict']}\n'

        return output

    def run(self, url: str, path: str = None):
        results = self.__scan_url(url)
        
        if path != None:
            file_name = f'virustotal_output_{hashlib.md5(url.encode()).hexdigest()}.json'
            file_path = os.path.join(path, file_name)
            with open(file_path, 'w') as file:
                file.write(json.dumps(results))

        return results


if __name__ == '__main__':
    object = CheckVirusTotal()
    print(object.run('https://salator.es/login'))




