# python imports
import re
from dateutil.parser import parse

# third-party imports
from bs4 import BeautifulSoup
import requests

# local imports
from utils.file import make_dir, remove_file, save_to_csv
from utils.impact import intel_impact_map


def main(base_url, security_center_url, advisory_csv):

    print('Download advisories...')

    resp = requests.get(f'{base_url}/{security_center_url}',
                        headers={'User-Agent': 'Mozilla/5.0'})
    soup = BeautifulSoup(resp.text, 'lxml')

    intel_main_table = soup.find_all('tr', {'class': 'data'})
    advisories_url = list()

    for item in intel_main_table:
        anchor = item.find('a')
        advisories_url.append(anchor['href'])

    advisories_info = list()

    for advisory in advisories_url:
        url = f'{base_url}/{advisory}'

        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(resp.text, 'lxml')

        features_table = soup.find('div', {'class': 'editorialtable'})

        _, impact, _, published_date, *_ = features_table.find_all('tr', {'class': 'data'})

        impact = impact.find_all('td')[1].text.split(',')
        impact = [value.strip().rstrip() for value in impact]

        if impact in intel_impact_map.keys():
            impact = intel_impact_map[impact[0]]
        else:
            impact = 'other'

        published_date = published_date.find_all('td')[1].text.strip().rstrip()
        published_date = parse(published_date).strftime('%m/%d/%Y')

        cve_id_regex = re.compile('CVE-[0-9]{4}-[0-9]+')
        cves = list()

        for item in soup.find_all(text=cve_id_regex):
            for cve in re.findall(cve_id_regex, item):
                if cve not in cves:
                    cves.append(cve)

        intel_sa = re.search('intel-sa-[0-9]+', url).group(0).upper()

        for cve in cves:
            advisories_info.append([cve, published_date, impact, intel_sa])

    print('Preparing output folder...')

    make_dir(advisory_csv)
    remove_file(advisory_csv)

    print('Saving to file...')

    header = ['cve_id', 'impact', 'published_date', 'reference']
    save_to_csv(advisory_csv, header, advisories_info)


if __name__ == '__main__':
    main(base_url='https://www.intel.com',
         security_center_url='content/www/us/en/security-center/default.html',
         advisory_csv='datasets/intel_advisory.csv')
