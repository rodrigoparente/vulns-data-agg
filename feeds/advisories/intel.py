# python imports
import re
from urllib.parse import urljoin
from dateutil.parser import parse

# project imports
from commons.file import save_list_to_csv
from commons.parse import request_clean_page

# local imports
from .constants import INTEL_BASE_URL
from .constants import INTEL_SECURITY_BULLETIN
from .constants import INTEL_OUTPUT_FILE_PATH
from .constants import INTEL_IMPACT_MAP


def download_intel_advisory():

    url = urljoin(INTEL_BASE_URL, INTEL_SECURITY_BULLETIN)
    soup = request_clean_page(url)

    intel_main_table = soup.find_all('tr', {'class': 'data'})
    advisories_url = list()

    for item in intel_main_table:
        anchor = item.find('a')
        advisories_url.append(anchor['href'])

    advisories_info = list()

    for advisory in advisories_url:

        url = urljoin(INTEL_BASE_URL, advisory)
        soup = request_clean_page(url)

        features_table = soup.find('div', {'class': 'editorialtable'})

        _, impact, _, published_date, *_ = features_table.find_all('tr', {'class': 'data'})

        impact = impact.find_all('td')[1].text.split(',')
        impact = [value.strip().rstrip() for value in impact][0]

        if impact in INTEL_IMPACT_MAP.keys():
            impact = INTEL_IMPACT_MAP[impact]
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

    header = ['cve_id', 'impact', 'published_date', 'reference']
    save_list_to_csv(INTEL_OUTPUT_FILE_PATH, header, advisories_info)
