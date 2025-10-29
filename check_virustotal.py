import vt
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

            analysis_id = client.scan_url(url)
            while True:
                result = client.get_object(f"/analyses/{analysis_id.id}")
                if result.status == 'completed':
                    break
                time.sleep(1)

            url_id = vt.url_id(url)
            url_object = client.get_object(f'/urls/{url_id}')

            client.close()
        except Exception as e:
            print(e)
            client.close()
            return None

        final_results = {}
        final_results['engine_stats'] = result.stats # How many engines found the link to be malicious/suspicious/undetected/harmless/timeout
        final_results['community_votes'] = url_object.total_votes
        final_results['times_submitted'] = url_object.times_submitted
        final_results['internal_trust_score'] = url_object.reputation
        final_results['analysis_id'] = analysis_id
        final_results['url'] = url
        final_results['verdict'] = 'harmless'

        if result.stats['malicious'] > 3 or url_object.reputation < 0:
            final_results['verdict'] = 'malware'

        # reputation: > 1000 very good reputation, 0-1000 neutral, < 0 suspicious

        return final_results
    
    def __print_format(self, results):
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
        print_output = self.__print_format(results)
        print(print_output)

        return results, print_output


if __name__ == '__main__':
    object = CheckVirusTotal('br-icloud.com.br')
    object.run()
    



