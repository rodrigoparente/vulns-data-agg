# python imports
import re
import logging
from dateutil.parser import ParserError
from urllib.parse import urljoin

# project imports
from commons.file import save_list_to_csv
from commons.parse import request_clean_page, extract_table_info

# local imports
from constants import adobe_impact_map


log = logging.getLogger(__name__)


def download_adv(base_url, security_bulletin, advisory_csv):

    print('Downloading Adobe Advisory...')

    url = f'{base_url}/{security_bulletin}'
    soup = request_clean_page(url)

    advisories_url = list()

    for table in soup.find_all('table'):
        for link in table.find_all('a'):
            href = link.attrs['href']

            if 'http' not in href:
                href = urljoin(base_url, href)

            advisories_url.append(href)

    rows = list()

    for url in advisories_url:

        soup = request_clean_page(url)

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

    print('Saving to file...')

    header = ['cve_id', 'published_date', 'impact', 'reference']
    save_list_to_csv(advisory_csv, header, rows)
