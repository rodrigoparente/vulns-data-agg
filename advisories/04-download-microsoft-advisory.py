# python imports
import json
import re
import logging
from dateutil.parser import parse, ParserError

# third-party imports
import requests

# local imports
from utils.file import make_dir, remove_file, save_to_csv
from utils.impact import microsoft_impact_map


log = logging.getLogger(__name__)


def main(base_url, advisory_csv, year_begin, year_end):

    months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun',
              'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

    entries = list()

    for year in range(year_begin, year_end):

        print(f'Download advisory from year {year}...')

        for month in months:
            url = f'{base_url}/{year}-{month}'

            response = requests.get(url, headers={'Accept': 'application/json'})

            for vuln in json.loads(response.text)['Vulnerability']:
                row = list()

                additional_info = dict()
                impact_list = list()

                for threat in vuln['Threats']:

                    if threat['Type'] == 0 and \
                            'Value' in threat['Description'].keys():
                        impact_list.append(threat['Description']['Value'])

                    if threat['Type'] == 1 and \
                            'Value' in threat['Description'].keys():

                        for desc in threat['Description']['Value'].split(';'):
                            key, value = desc.split(':')
                            additional_info.setdefault(key, value)

                public_disclosed = additional_info['Publicly Disclosed'] \
                    if 'Publicly Disclosed' in additional_info.keys() else None

                exploited = additional_info['Exploited'] \
                    if 'Exploited' in additional_info.keys() else None

                latest = additional_info['Latest Software Release'] \
                    if 'Latest Software Release' in additional_info.keys() else None

                older = additional_info['Older Software Release'] \
                    if 'Older Software Release' in additional_info.keys() else None

                dos = additional_info['DOS'] \
                    if 'DOS' in additional_info.keys() else None

                cve_id_regex = re.compile('CVE-[0-9]{4}-[0-9]+')
                if not re.match(cve_id_regex, vuln['CVE']):
                    continue

                row.append(vuln['CVE'])

                try:
                    published_date = parse(f'{month} 01, {year}').strftime('%m/%d/%Y')
                    row.append(published_date)
                except ParserError:
                    log.error('Could not parse date.')
                    continue

                row.append(public_disclosed)
                row.append(exploited)
                row.append(latest if latest else older)
                row.append(dos)

                impact = 'other'
                if impact_list and \
                        impact in microsoft_impact_map.keys():
                    impact = microsoft_impact_map[impact_list[0]]

                row.append(impact)

                knowledge_base = list()

                for remediation in vuln['Remediations']:
                    if 'URL' in remediation.keys():
                        kb = re.search('KB[0-9]+', remediation['URL'])
                        if kb:
                            knowledge_base.append(kb.group(0))

                row.append(list(set(knowledge_base)) if knowledge_base else '')

                entries.append(row)

    print('Preparing output folder...')

    make_dir(advisory_csv)
    remove_file(advisory_csv)

    print('Saving to file...')

    header = [
        'cve_id', 'published_date', 'publicly_disclosed', 'exploited',
        'exploitation_likelihood', 'dos', 'impact', 'reference']
    save_to_csv(advisory_csv, header, entries)


if __name__ == '__main__':
    main(base_url='https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/',
         advisory_csv='datasets/microsoft_advisory.csv',
         year_begin=2017,
         year_end=2022)
