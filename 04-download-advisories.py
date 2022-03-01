# python imports
import os
import csv
import json
import re

# third-party imports
import requests


def main(base_url, microsoft_advisory_csv, year_begin, year_end):

    print('Preparing output folder...')

    # create output folder if it doesnt exists
    dirs = os.path.split(microsoft_advisory_csv)[0]
    if not os.path.exists(dirs):
        os.makedirs(dirs)

    # delete output file if it exists
    if os.path.exists(microsoft_advisory_csv):
        os.remove(microsoft_advisory_csv)

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

                row.append(vuln['CVE'])
                row.append(f'{year}-{month}')

                additional_info = dict()
                severity_list = list()
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

                    if threat['Type'] == 3 and \
                        'Value' in threat['Description'].keys():
                        severity_list.append(threat['Description']['Value'])

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

                row.append(public_disclosed)
                row.append(exploited)
                row.append(latest if latest else older)                
                row.append(dos)

                row.append(list(set(severity_list)) if severity_list else ['N/A'])
                row.append(list(set(impact_list)) if impact_list else ['N/A'])

                knowledge_base = list()

                for remediation in vuln['Remediations']:
                    if 'URL' in remediation.keys():
                        kb = re.search('KB\d+', remediation['URL'])
                        if kb:
                            knowledge_base.append(kb.group(0))

                row.append(1 if len(knowledge_base) > 0 else 0)
                row.append(list(set(knowledge_base)))

                entries.append(row)

    with open(microsoft_advisory_csv, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(
            ['CVE-ID', 'publishedDate', 'publiclyDisclosed', 'exploited', 
             'exploitationLikelihood', 'DOS', 'severity', 'impact', 
             'remediation', 'knowledgeBase'])
        writer.writerows(entries)


if __name__ == '__main__':
    main(base_url='https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/',
         microsoft_advisory_csv='datasets/microsoft_advisory.csv',
         year_begin=2017,
         year_end=2022)