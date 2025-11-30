import os
from enum import IntEnum
import hashlib
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from concurrent.futures import TimeoutError
import shutil
import textwrap
import time
import math
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import tldextract
import string
import ipaddress
from datetime import datetime
import re
import pandas as pd
import joblib

from confusable_homoglyphs import confusables
from ftfy import fix_text
import Levenshtein

from url_normalize import url_normalize
from check_virustotal import CheckVirusTotal
from check_googlesb import CheckGoogleSB
from check_threatfox import CheckThreatFox
from check_whois import CheckWhoIs
from check_dns import CheckDNS
# from random_forest import RandomForestClassifier

class ThreatLevel(IntEnum):
    UNKNOWN = 0
    CLEAN = 1
    SUSPICIOUS = 2
    MALICIOUS = 3

    def __str__(self):
        strings = {
            ThreatLevel.UNKNOWN: "Unknown",
            ThreatLevel.CLEAN: "Clean", 
            ThreatLevel.SUSPICIOUS: "Suspicious",
            ThreatLevel.MALICIOUS: "Malicious"
        }
        return strings[self]

class Categories(IntEnum):
    RANSOMWARE = 0
    C2 = 1
    MALWARE = 2
    EXPLOIT = 3
    PHISHING = 4
    SPAM = 5

    def __str__(self):
        strings = {
            Categories.RANSOMWARE: "Ransomware", 
            Categories.C2: "C2", 
            Categories.MALWARE: "Malware",
            Categories.EXPLOIT: "Exploit", 
            Categories.PHISHING: "Phishing", 
            Categories.SPAM: "Spam"
        }
        return strings[self]


class CheckURL:
    def __init__(self,
                 vt_check: bool = True, googlesb_check: bool = True, threatfox_check: bool = True,
                 report_path: str = None):
        self.__url = ''
        self.__vt_check = vt_check
        self.__googlesb_check = googlesb_check
        self.__threatfox_check = threatfox_check
        self.__report_path = report_path

        self.__len_engines = 3

        self.__vt_obj = None
        self.__gsb_obj = None
        self.__fox_obj = None

        if vt_check == True:
            self.__vt_obj = CheckVirusTotal()
        if googlesb_check == True:
            self.__gsb_obj = CheckGoogleSB()
        if threatfox_check == True:
            self.__fox_obj = CheckThreatFox()
        
        self.__whois_obj = CheckWhoIs()
        self.__dns_obj = CheckDNS()

    def __get_skeleton(self, url: str):
        fixed = fix_text(url)
        
        # Convert to ASCII using 'ignore' errors
        ascii_bytes = fixed.encode('ascii', 'ignore')
        ascii_text = ascii_bytes.decode('ascii')
        
        # Remove any non-URL-safe characters
        cleaned = re.sub(r'[^a-zA-Z0-9\.\-_:/?=&]', '', ascii_text)
        
        return cleaned
    
    def __host_is_ip(self, hostname: str) -> bool:
        try:
            # Try IPv4 or IPv6
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
        
    def __get_shannon_entropy(self, domain: str):
        chars = {}
        lg = 0

        for ch in domain:
            if ch not in chars:
                chars[ch] = 1
            else:
                chars[ch] += 1
            lg += 1

        entropy = 0
        for ch, freq in chars.items():
            prob = freq / lg
            entropy -= prob * math.log2(prob)

        return entropy

    def __normalize_url(self, url):
        url = url_normalize(url)
        # Does lowercase scheme & host, removing default ports, resolving relative paths, Percent-encoding normalization, Removing duplicate slashes

        parsed = urlparse(url)
        # Strip fragments
        parsed = parsed._replace(fragment = '')

        # Strip tracking/query parameters
        tracking_params = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"}
        query_params = parse_qsl(parsed.query)
        filtered_params = [(k, v) for k, v in query_params if k not in tracking_params]
        #TODO: remove session ids?
        parsed = parsed._replace(query = urlencode(filtered_params))

        # Convert Punycode to Unicode
        hostname = parsed.hostname
        unicode = hostname.encode('ascii').decode('idna')
        parsed = parsed._replace(netloc = unicode)

        url = urlunparse(parsed)

        return url

    def __normalize_blacklist_output(self):
        pass

    def __norm_category(self, category: str) -> Categories:
        category = category.lower()
        for item in [
        'ransomware', 'ransom', 'cryptolocker', 'cryptowall', 'wannacry',
        'petya', 'filecoder', 'encoder', 'crypto-malware', 'trojan-ransom',
        'file-locker', 'encrypting-trojan', 'locker', 'social' ,'engineering'
                    ]:
            if item in category:
                return Categories.RANSOMWARE
        
        for item in [
        'c2', 'command-control', 'command_and_control', 'botnet', 'botnet-c2',
        'botnet-cc', 'backdoor', 'remote-access-trojan', 'rat', 'beacon',
        'call-home', 'cnc', 'command-server', 'trojan-c2', 'malware-c2',
        'control-server', 'communication', 'cc'
                    ]:
            if item in category:
                return Categories.C2
        
        for item in  [
        'malware', 'malicious', 'trojan', 'trojan-horse', 'trojan-dropper',
        'virus', 'worm', 'adware', 'pua', 'riskware', 'hacktool', 'generic',
        'malicious-site', 'malicious-software', 'potentially-harmful',
        'unwanted-software', 'malware-gen', 'trojan-gen', 'unwanted','software'
                    ]:
            if item in category:
                return Categories.MALWARE
            
        for item in [
        'exploit', 'exploit-kit', 'vulnerability', 'vuln-exploit', 'drive-by',
        'driveby-download', 'kit', 'payload', 'shellcode', 'arbitrary-code',
        'code-execution', 'vulnerability-exploit', 'angler', 'nuclear',
        'magnitude'
                    ]:
            if item in category:
                return Categories.EXPLOIT
            
        
        for item in [
        'phishing', 'phish', 'social-engineering', 'credential-harvesting',
        'login-fake', 'fake-login', 'impersonation', 'banking-fraud',
        'financial-phish', 'deception', 'spoofing', 'credential-stealing',
        'identity-theft', 'fake-page', 'login-phish'
                    ]:
            if item in category:
                return Categories.PHISHING
            
        for item in [
        'spam', 'spamming', 'scam', 'fraud', 'deceptive', 'unsolicited-commercial',
        'adv', 'advertising', 'newsletter-spam', 'marketing-spam', 'commercial-spam',
        'email-spam', 'message-spam'
                    ]:
            if item in category:
                return Categories.SPAM
            
        return category

    def check_vt(self, url, path):
        # return 'omg',{'name': 'vt'}

        try:
            output = self.__vt_obj.run(url, path)

            result = {}
            result['name'] = 'vt'
            result['source'] = 'VirusTotal'
            if output['ok'] != 1:
                result['error'] = output['error']
                summary = textwrap.dedent(f'''
                VIRUSTOTAL SUMMARY
                --------------------
                ERROR: {result['error']}
                            '''
                            )
                return summary, result
            
            unknown_count = output['engine_stats']['undetected']
            clean_count = output['engine_stats']['harmless']
            suspicious_count = output['engine_stats']['suspicious']
            malicious_count = output['engine_stats']['malicious']
            total_count = unknown_count + clean_count + suspicious_count + malicious_count

            unknown_ratio = unknown_count / total_count
            clean_ratio = clean_count / total_count
            suspicious_ratio = suspicious_count / total_count
            malicious_ratio = malicious_count / total_count

            if malicious_ratio >= 0.1:
                result['status'] = ThreatLevel.MALICIOUS
                result['confidence'] = min(1.0, malicious_ratio*2)
            elif malicious_ratio >= 0.05 or suspicious_ratio >= 0.2:
                result['status'] = ThreatLevel.SUSPICIOUS
                result['confidence'] = min(0.8, (malicious_ratio + suspicious_ratio)*2)
            else:
                result['status'] = ThreatLevel.CLEAN
                result['confidence'] = max(0.1, 1.0 - malicious_ratio*10)

            result['unknown_ratio'] = unknown_ratio
            result['clean_ratio'] = clean_ratio
            result['suspicious_ratio'] = suspicious_ratio
            result['malicious_ratio'] = malicious_ratio

            result['times_submitted'] = output.get('times_submitted')
            result['internal_trust_score'] = output.get('internal_trust_score')
            result['comm_votes_malicious'] = output['community_votes']['malicious']

            result['categories'] = {}
            for category in output['categories'].values():
                norm = str(self.__norm_category(category))
                if norm != None:
                    if norm in result['categories']:
                        result['categories'][norm] += 1
                    else:
                        result['categories'][norm] = 1

            result['last_final_url'] = output['last_final_url']

            summary = textwrap.dedent(f'''
            VIRUSTOTAL SUMMARY
            --------------------------
            Verdict: {str(result['status'])}
            Categories: {result['categories']}
            Confidence: {result['confidence']}
            (Final URL: {result['last_final_url']})
                            '''
                            )
            return summary, result
        except Exception as e:
            result = {}
            result['name'] = 'vt'
            result['source'] = 'VirusTotal'
        
            result['error'] = str(e)
            summary = textwrap.dedent(f'''
            VIRUSTOTAL SUMMARY
            --------------------
            ERROR: {result['error']}
                        '''
                        )
            return summary, result
    
    def check_gsb(self, url, path):
        output = self.__gsb_obj.run(url, path)

        result = {}
        result['source'] = 'Google Safe Browsing'
        result['name'] = 'gsb'


        if output['ok'] != 1:
            result['error'] = output['error']
            if result['error'] == 'No malware found':
                result['status'] = ThreatLevel.UNKNOWN
            summary = textwrap.dedent(f'''
            GOOGLE SAFE BROWSING SUMMARY
            --------------------------
            ERROR: {result['error']}
                         '''
                         )
            return summary, result
        
        result['status'] = self.__norm_category(output['threat_type'])

        summary = textwrap.dedent(f'''
        GOOGLE SAFE BROWSING SUMMARY
        ----------------------
        Verdict: {str(result['status'])}
                         '''
                         )
        return summary, result        
    
    def check_fox(self, url, path):
        parsed = urlparse(url)._replace(query='')
        url = urlunparse(parsed)

        output = self.__fox_obj.run(url, path)

        result = {}
        result['name'] = 'fox'
        result['source'] = 'ThreatFox'
        if output['ok'] != 1:
            result['error'] = output['error']
            if result['error'] == 'no_result':
                result['status'] = ThreatLevel.UNKNOWN
            summary = textwrap.dedent(f'''
            THREATFOX SUMMARY
            --------------
            ERROR: {result['error']}
                         '''
                         )
            return summary, result
        
        result['status'] = self.__norm_category(output['threat_type'])
        result['categories'] = output['malware_name']
        result['details'] = output['type_desc']
        result['confidence'] = output['confidence_level']

        summary = textwrap.dedent(f'''
        THREATFOX SUMMARY
        ---------------------
        Verdict: {str(result['status'])}
        Categories: {result['categories']}
        Details: {result['details']}
        Confidence Level: {result['confidence']}
                         '''
                         )
        return summary, result
    
    def whois_lookup(self, url, path): 
        hostname = urlparse(url).hostname
        ext = tldextract.extract(url)
        domain = ext.top_domain_under_public_suffix

        output = self.__whois_obj.whois(domain, path)
        output['name'] = 'whois'

        if output['ok'] != 1:
            summary = textwrap.dedent(f'''
            WHOIS SUMMARY
            --------------
            ERROR: {output['error']}
                         '''
                         )
            return summary, output
        
        try:
            summary = textwrap.dedent(f'''
            WHOIS LOOKUP
            ------------------
            Domain: {output.get('domain')}
            Registrar: {output.get('registrar')}
            Country: {output.get('country')}
            Creation Date: {output.get('creation_date')}
            Expiration Date: {output.get('expiration_date')}
            Age (Days): {output.get('age_days')}
            ''')
        except Exception as e:
            summary = textwrap.dedent(f'''
            WHOIS SUMMARY
            --------------
            ERROR: {str(e)}
                         '''
                         )
            return summary, output

        return summary, output
        
    def lookup(self, url, path):
        if path is not None:
            os.makedirs(path, exist_ok=True)
        results = {}

        #Blacklist Lookup
        print(f'URL: {url}')
        with ThreadPoolExecutor(max_workers = self.__len_engines) as executor:
            futures = []
            if self.__vt_obj != None:
                futures.append(executor.submit(self.check_vt, url, path))
            if self.__gsb_obj != None:
                futures.append(executor.submit(self.check_gsb, url, path))
            if self.__fox_obj != None:
                futures.append(executor.submit(self.check_fox, url, path))
            try:
                for future in as_completed(futures, timeout = 20):
                    summary, result = future.result()
                    results[result['name']] = result
                    print(summary)
            except TimeoutError:
                print('Search timed out')

        # WhoIs Lookup
        summary, result = self.whois_lookup(url, path)
        results[result['name']] = result

        # Get DNS TTL
        results['dns'] = self.__dns_obj.dns_lookup(urlparse(url).hostname, path)
        # print(results['dns']) # TODO: print formatted dns output
        return summary, results
    
    def __get_feature_vector(self, url: str, lookup_result):
        features = {}
        parsed = urlparse(url)

        # URL Lexical Features
        features['url_length'] = len(url)
        features['num_subdirs'] = len(parsed.path.strip('/').split('/'))
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['contains_ip_address'] = self.__host_is_ip(parsed.hostname)
        features['number_of_subdomains'] = max(len(parsed.hostname.split('.'))-2, 0)
        features['has_login_keyword'] = any(word in url for word in ['login', 'bank', 'signin', 'signup', 'logout', 'money', 'account'])
        features['is_shortened_url'] = any(word in url for word in ['bit.ly', 'tinyurl'])
        features['domain_shannon_entropy'] = self.__get_shannon_entropy(parsed.hostname)

        # Domain WHOIS Features
        features['domain_age_days'] = lookup_result['whois'].get('age_days', 0)
        try:
            features['domain_expiration_days'] = (lookup_result['whois']['expiration_date'].replace(tzinfo=None) - datetime.now()).days
        except:
            features['domain_expiration_days'] = 0

        # DNS Features
        features['ttl'] = lookup_result['dns']['ttl']

        # VT
        features['vt_malicious_ratio'] = lookup_result['vt'].get('malicious_ratio', 0)
        features['vt_suspicious_ratio'] = lookup_result['vt'].get('suspicious_ratio', 0)
        features['vt_clean_ratio'] = lookup_result['vt'].get('clean_ratio', 0)
        features['vt_unknown_ratio'] = lookup_result['vt'].get('unknown_ratio', 0)
        features['vt_times_submitted'] = lookup_result['vt'].get('times_submitted', 0)
        features['vt_internal_trust_score'] = lookup_result['vt'].get('internal_trust_score', 0)
        features['comm_votes_malicious'] = lookup_result['vt'].get('comm_votes_malicious', 0)

        # Threatfox
        features['fox_status'] = lookup_result['fox'].get('status', 0)
        features['fox_confidence'] = lookup_result['fox'].get('confidence', 0)

        # GoogleSB
        features['gsb_status'] = lookup_result['gsb'].get('status', 0)

        #compute skeleton and levenshtein distance
        skeleton = self.__get_skeleton(parsed.hostname)
        if skeleton != parsed.hostname:
            features['is_skeleton_different'] = 1
        else:
            features['is_skeleton_different'] = 0

        features['levenshtein_distance'] = Levenshtein.distance(parsed.hostname, skeleton)

        # print(list(features.keys()))

        return features

    def run(self, url):
        if self.__report_path is not None:
            path = os.path.join(self.__report_path, f'{math.floor(time.time())}_{hashlib.md5(url.encode()).hexdigest()}')
        else:
            path = None
        url = self.__normalize_url(url)
        # print(url)
        summary, lookup_result = self.lookup(url, path)
        # print(lookup_result)

        features = self.__get_feature_vector(url, lookup_result)
        
        model = joblib.load('random_forest_url_model.joblib')

        df = pd.DataFrame(features, index=[0])
        probs = model.predict_proba(df)
        prob_clasa1 = probs[0][0]
        prob_clasa2 = probs[0][1]
        prob_clasa3 = probs[0][2]

        print(f"Probability of the URL being CLEAN: {prob_clasa1:.2f}")
        print(f"Probability of the URL being SUSPICIOUS: {prob_clasa2:.2f}")
        print(f"Probability of the URL being MALICIOUS: {prob_clasa3:.2f}")

        return features

if __name__ == '__main__':
    object = CheckURL(report_path='./reports')
    object.run('https://gemini.google.com/app/e2ec3a3bd1e597d7')






