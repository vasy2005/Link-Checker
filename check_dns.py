import dns.resolver
import os
import hashlib
import json

class CheckDNS:
    def __init__(self):
        pass

    def dns_lookup(self, domain, path: str = None):
        answer = dns.resolver.resolve(domain, 'A')
        result_dict = self.__dns_answer_to_complete_dict(answer)

        return result_dict
    
    def get_ttl(self, domain, path: str = None):
        result = self.dns_lookup(self, domain, path)

        if path != None:
            file_name = f'googlesb_raw_output_{hashlib.md5(domain.encode()).hexdigest()}.json'
            file_path = os.path.join(path, file_name)
            with open(file_path, 'w') as file:
                file.write(json.dumps(result))

        return result['rrset_info']['ttl']

    def __dns_answer_to_complete_dict(self, answer):
        """
        Convert DNS answer object to complete dictionary
        """
        result = {
            'query_info': {
                'canonical_name': str(answer.canonical_name),
                'nameserver': answer.nameserver,
                'port': answer.port,
                'response_time': getattr(answer.response, 'time', None),
            },
            'rrset_info': {
                'ttl': answer.rrset.ttl,
                'rdtype': answer.rrset.rdtype,
                'rdclass': answer.rrset.rdclass,
                'covers': answer.rrset.covers,
            },
            'records': []
        }
        
        for i, record in enumerate(answer):
            record_dict = {
                'index': i,
                'string_value': str(record),
                'record_type': answer.rrset.rdtype
            }
            
            record_attrs = {}
            for attr in ['address', 'preference', 'exchange', 'target', 'strings', 'priority']:
                if hasattr(record, attr):
                    value = getattr(record, attr)

                    if attr == 'strings' and value:
                        record_attrs[attr] = [s.decode('utf-8') for s in value]
                    else:
                        record_attrs[attr] = str(value) if not isinstance(value, (int, float)) else value
        
        if record_attrs:
            record_dict['attributes'] = record_attrs
            
        result['records'].append(record_dict)

        return result

if __name__ == '__main__':
    object = CheckDNS()
    object.dns_lookup('google.com', './')
