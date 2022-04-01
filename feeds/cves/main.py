# python imports
import json
import logging
from gzip import GzipFile
from dateutil.parser import parse, ParserError
from urllib.request import urlopen

# project imports
from commons.file import save_list_to_csv

# local imports
from utils import extract_cwe
from utils import extract_part_vendor_product
from utils import extract_metrics


log = logging.getLogger(__name__)


def main(json_feed, output_file_path, start_year, end_year):
    cves = list()

    for year in range(start_year, end_year):

        try:
            with urlopen(json_feed.format(year)) as response:
                with GzipFile(fileobj=response) as uncompressed:
                    file = json.loads(uncompressed.read())
        except Exception as e:
            log.error(f'Could not download json file: {e}')

        for cve in file.get('CVE_Items'):
            id = cve.get('cve').get('CVE_data_meta').get('ID')

            problem_type = cve.get('cve').get('problemtype')
            cwes = extract_cwe(problem_type)

            nodes = cve.get('configurations').get('nodes')
            parts, vendors, products = extract_part_vendor_product(nodes)

            impact = cve.get('impact')
            base_metrics = extract_metrics(impact)

            try:
                published_date = cve.get('publishedDate')
                published_date = parse(published_date).strftime('%m/%d/%Y')
            except ParserError:
                log.error('Error parsing vulnerability published date')

            try:
                modified_date = cve.get('lastModifiedDate')
                modified_date = parse(modified_date).strftime('%m/%d/%Y')
            except ParserError:
                log.error('Error parsing vulnerability modification date')

            cves.append([
                id, cwes, parts, vendors, products,
                *base_metrics.values(),
                published_date, modified_date])

    print('Saving to file...')

    header = [
        "ID", "cwe", "part", "vendor", "product", "cvssType", "attackVector",
        "attackComplexity", "privilegesRequired", "userInteraction", "scope",
        "confidentialityImpact", "integrityImpact", "availabilityImpact",
        "baseScore", "baseSeverity", "exploitabilityScore", "impactScore",
        "publishedDate", "lastModifiedDate"]

    save_list_to_csv(output_file_path, header, cves)


if __name__ == '__main__':

    main(json_feed='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz',
         output_file_path='output/cves.csv',
         start_year=2016,
         end_year=2022)
