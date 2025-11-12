import os
from enum import IntEnum
import hashlib
import vt
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from concurrent.futures import TimeoutError
import shutil
import textwrap
import time
import math

from url_normalize import url_normalize
from check_virustotal import CheckVirusTotal
from check_googlesb import CheckGoogleSB
from check_threatfox import CheckThreatFox
from check_whois import CheckWhoIs

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
                 report_path: str = './'):
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

    def __normalize_url(self, url):
        url = url_normalize(url)

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
        output = self.__vt_obj.run(url, path)

        result = {}
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
    
    def check_gsb(self, url, path):
        output = self.__gsb_obj.run(url, path)

        result = {}
        result['source'] = 'Google Safe Browsing'
        if output['ok'] != 1:
            result['error'] = output['error']
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
        output = self.__fox_obj.run(url, path)

        result = {}
        result['source'] = 'ThreatFox'
        if output['ok'] != 1:
            result['error'] = output['error']
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

        summary = textwrap.dedent(f'''
        THREATFOX SUMMARY
        ---------------------
        Verdict: {str(result['status'])}
        Categories: {result['categories']}
        Details: {result['details']}
                         '''
                         )
        return summary, result
    
    def whois_lookup(self, url, path): 
        output = self.__whois_obj.whois(url, path)

        if output['ok'] != 1:
            summary = textwrap.dedent(f'''
            WHOIS SUMMARY
            --------------
            ERROR: {output['error']}
                         '''
                         )
            return summary, output

        summary = textwrap.dedent(f'''
        WHOIS LOOKUP
        ------------------
        Domain: {output['domain']}
        Registrar: {output['registrar']}
        Country: {output['country']}
        Creation Date: {output['creation_date']}
        Expiration Date: {output['expiration_date']}
        Age (Days): {output['age_days']}
        ''')

        return summary, output
        

    def lookup(self, url, path):
        os.makedirs(path, exist_ok=True)

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
                    print(summary)
            except TimeoutError:
                print('Search timed out')

        #WhoIs Lookup
        summary, result = self.whois_lookup(url, path)
        print(summary)

    def run(self, url):
        path = os.path.join(path, f'{math.floor(time.time())}_{hashlib.md5(url.encode()).hexdigest()}')
        url = self.__normalize_url(url)

if __name__ == '__main__':
    object = CheckURL()
    object.lookup('www.salator.es', path = './')






