# python imports
import json
import re
import logging
from dateutil.parser import parse, ParserError

# third-party imports
import requests

# project imports
from commons.file import save_list_to_csv

# local imports
from constants import microsoft_impact_map as impact_map


log = logging.getLogger(__name__)


def download_adv(base_url, advisory_csv, year_begin, year_end):

    months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun',
              'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

    entries = list()

    for year in range(year_begin, year_end):
        for month in months:
            url = f'{base_url}/{year}-{month}'

            resp = requests.get(url, headers={'Accept': 'application/json'})
            vulns = json.loads(resp.text).get('Vulnerability')

            for vuln in vulns:
                # skip advisory if it doesn't have a CVE-ID
                cve_id_regex = re.compile(r'CVE-\d{4}-\d+')
                if not re.match(cve_id_regex, vuln.get('CVE', None)):
                    continue

                info = dict()
                impacts = list()

                for threat in vuln['Threats']:
                    if 'Value' in threat.get('Description').keys():
                        descs = threat.get('Description').get('Value')
                        if threat['Type'] == 0:
                            impacts.append(descs)
                        elif threat['Type'] == 1:
                            for desc in descs.split(';'):
                                key, value = desc.split(':')
                                info.setdefault(key, value)

                cveID = vuln.get('CVE', None)
                public_disclosed = info.get('Publicly Disclosed', None)
                exploited = info.get('Exploited', None)

                latest = info.get('Latest Software Release', None)
                older = info.get('Older Software Release', None)
                likelihood = latest if latest else older

                dos = info.get('DOS', None)

                try:
                    published_date = parse(f'{month} 01, {year}').strftime('%m/%d/%Y')
                except ParserError:
                    log.error('Could not parse date.')
                    continue

                impact = impact_map.get(impacts[0], 'other') if impacts else None

                kb_list = list()
                for remediation in vuln['Remediations']:
                    if 'URL' in remediation.keys():
                        knowledge = re.search('KB[0-9]+', remediation['URL'])
                        if knowledge:
                            kb_list.append(knowledge.group(0))
                kb_list = list(set(kb_list))

                entries.append([
                    cveID, published_date, public_disclosed,
                    exploited, likelihood, dos, impact, kb_list])

    print('Saving to file...')

    header = [
        'cve_id', 'published_date', 'publicly_disclosed', 'exploited',
        'exploitation_likelihood', 'dos', 'impact', 'reference']
    save_list_to_csv(advisory_csv, header, entries)
