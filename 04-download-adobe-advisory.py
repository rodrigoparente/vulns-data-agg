# python imports
import re
import logging
from dateutil.parser import parse, ParserError
from urllib.parse import urljoin

# third-party imports
from bs4 import BeautifulSoup
import requests

# local imports
from utils.file import make_dir, remove_file, save_to_csv
from utils.impact import adobe_impact_map


log = logging.getLogger(__name__)


def extract_table_info(table):
    results = list()
    headers = list()

    for row_id, row in enumerate(table.find_all('tr')):
        if row_id == 0:
            header_items = row.find_all('th')
            if header_items:
                for name in header_items:
                    text = name.text.encode('ascii', 'ignore').decode()
                    text = text.lower().replace(' ', '_')
                    text = text.strip().rstrip().replace('\n', '_')
                    headers.append(text)
            else:
                # because some pages doesn't use <th><th/>
                # tag to define the header of the table
                for name in row.find_all('td'):
                    text = name.text.encode('ascii', 'ignore').decode()
                    text = text.lower().replace(' ', '_').strip().rstrip()
                    headers.append(text)
        else:
            row_dict = dict()
            for header, name in zip(headers, row.find_all('td')):

                text = name.text.encode('ascii', 'ignore').decode()
                text = text.strip().rstrip()

                if header == 'date_published':
                    try:
                        text = parse(text).strftime('%m/%d/%Y')
                    except ParserError:
                        raise ParserError

                row_dict.setdefault(header, text)
            results.append(row_dict)

    return results


def main(base_url, security_bulletin, advisory_csv):

    print('Downloading advisories...')

    resp = requests.get(
        f'{base_url}/{security_bulletin}', headers={'User-Agent': 'Mozilla/5.0'})
    soup = BeautifulSoup(resp.text, 'lxml')

    advisories_url = list()

    for table in soup.find_all('table'):
        for link in table.find_all('a'):
            href = link.attrs['href']

            if 'http' not in href:
                href = urljoin(base_url, href)

            advisories_url.append(href)

    rows = list()

    for url in advisories_url:

        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(resp.text, 'lxml')

        tables = soup.find_all('table')

        try:
            summary_table = tables[0]
            vuln_details_table = tables[-1]
        except IndexError:
            log.info('Could not extract info from page.')
            continue

        try:
            summary = extract_table_info(summary_table)[0]
            vuln_details = extract_table_info(vuln_details_table)
        except ParserError:
            log.info('Could not parse date.')
            continue

        for vuln in vuln_details:
            if 'cve_numbers' in vuln.keys():
                vuln.update({'cve_number': vuln['cve_numbers']})

            if 'cve_number' not in vuln.keys():
                continue

            adv_impact = vuln.get('vulnerability_impact')
            if adv_impact in adobe_impact_map.keys():
                adv_impact = adobe_impact_map[adv_impact]
            else:
                adv_impact = 'other'

            cve_list = re.split(r'\n+|\s+|,', vuln.get('cve_number'))
            cve_list = list(filter(None, cve_list))

            for cve_id in cve_list:
                rows.append([
                    cve_id, summary.get('date_published'),
                    adv_impact, summary.get('bulletin_id')
                ])

    print('Preparing output folder...')

    make_dir(advisory_csv)
    remove_file(advisory_csv)

    print('Saving to file...')

    header = ['cve_id', 'published_date', 'impact', 'reference']
    save_to_csv(advisory_csv, header, rows)


if __name__ == '__main__':
    main(base_url='https://helpx.adobe.com',
         security_bulletin='security/security-bulletin.html',
         advisory_csv='datasets/adobe_advisory.csv')
