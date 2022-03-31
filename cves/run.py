# python imports
import json
import logging
from gzip import GzipFile
from dateutil.parser import parse, ParserError
from urllib.request import urlopen

# project imports
from commons.file import save_to_json

# local imports
from parse import extract_cwe
from parse import extract_part_vendor_product
from parse import extract_metrics


log = logging.getLogger(__name__)


def main(json_feed, output_file_path, start_year, end_year):
    cves = list()

    for year in range(start_year, end_year):

        print(f'CVE feed from year {year}')
        print('  - Downloading feed...')

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

            cves.append({
                'ID': id,
                'cwe': cwes,
                'part': parts,
                'vendor': vendors,
                'product': products,
                **base_metrics,
                'publishedDate': published_date,
                'lastModifiedDate': modified_date
            })

    print('Saving to file...')

    save_to_json(output_file_path, cves)


if __name__ == '__main__':

    main(json_feed='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz',
         output_file_path='datasets/cves.json',
         start_year=2016,
         end_year=2022)
