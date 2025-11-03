import vt
from vt.error import APIError
import os
import time
from dotenv import load_dotenv

from url_normalize import url_normalize

class CheckVirusTotal:
    def __init__(self, url: str):
        load_dotenv()
        self.__api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.__url = url

    def __scan_url(self, url):
        url = url_normalize(url)
        client = vt.Client(self.__api_key)

        try:
            
            url_id = vt.url_id(url)
            url_object = client.get_object(f'/urls/{url_id}')

            if url_object and url_object.last_analysis_date:
                age_days = (time.time() - url_object.last_analysis_date.timestamp()) / (24*60*60)

                if age_days > 7:
                    raise APIError
                    
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
            print(e)
            client.close()
            return None

        final_results = {}
        final_results['engine_stats'] = url_object.last_analysis_stats # How many engines found the link to be malicious/suspicious/undetected/harmless/timeout
        final_results['community_votes'] = url_object.total_votes
        final_results['times_submitted'] = url_object.times_submitted
        final_results['internal_trust_score'] = url_object.reputation
        final_results['url'] = url
        final_results['last_http_code'] = url_object.last_http_response_code
        final_results['last_final_url'] = url_object.last_final_url
        final_results['categories'] = url_object.categories
        final_results['tags'] = url_object.tags

        final_results['detailed_engine_results'] = url_object.last_analysis_results
        final_results['flagged_by'] = [engine for engine, data in final_results['detailed_engine_results'].items() if data['category'] == 'malicious']

        if final_results['engine_stats']['malicious'] > 3 or final_results['internal_trust_score'] < 0:
            final_results['verdict'] = 'malware'
        else:
            final_results['verdict'] = 'harmless'

        # reputation: > 1000 very good reputation, 0-1000 neutral, < 0 suspicious

        return final_results
    
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

    def run(self):
        url = self.__url
        results = self.__scan_url(url)
        print(results)
        report = self.__vt_report(results)
        print(report)

        return results, report


if __name__ == '__main__':
    object = CheckVirusTotal('br-icloud.com.br')
    object.run()
    



