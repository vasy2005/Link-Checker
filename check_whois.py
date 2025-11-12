import whois
from datetime import datetime
import hashlib
import os
import json

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class CheckWhoIs:
    def __init__(self):
        pass

    def whois(sef, url: str, path: str = None):
        output = {}
        output['ok'] = 1
        output['error'] = ''
        try:
            w = whois.whois(url)
        except Exception as e:
            output['ok'] = 0
            output['error'] = str(e)
            return output
        
        output['domain'] = w.domain_name
        output['registrar'] = w.registrant_name
        output['country'] = w.country
        if w.creation_date is not None:
            if isinstance(w.creation_date, list):
                output['creation_date'] = w.creation_date[0]
            else:
                output['creation_date'] = w.creation_date

            output['age_days'] = (datetime.now(output['creation_date'].tzinfo) - output['creation_date']).days

        output['expiration_date'] = w.expiration_date

        if path != None:
            file_name = f'whois_output_{hashlib.md5(url.encode()).hexdigest()}.json'
            file_path = os.path.join(path, file_name)
            with open(file_path, 'w') as file:
                file.write(json.dumps(output, cls=DateTimeEncoder))

        return output
    
if __name__ == '__main__':
    object = CheckWhoIs()
    object.whois('salator.com', path='./')

        