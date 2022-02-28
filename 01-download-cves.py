# python imports
import os
import json
from gzip import GzipFile
from urllib.request import urlopen


def extract_and(children):
    part_list = list()
    vendor_list = list()
    product_list = list()

    for child in children:
        if child['operator'] == 'AND':
            if 'children' in child.keys():
                tmp_part_list, tmp_vendor_list, tmp_product_list = extract_and(child['children'])
            else:
                tmp_part_list, tmp_vendor_list, tmp_product_list = extract_or(child['cpe_match'])
        elif child['operator'] == 'OR':
            tmp_part_list, tmp_vendor_list, tmp_product_list = extract_or(child['cpe_match'])

        part_list += tmp_part_list
        vendor_list += tmp_vendor_list
        product_list += tmp_product_list

    return part_list, vendor_list, product_list


def extract_or(cpe_match):
    part_list = list()
    vendor_list = list()
    product_list = list()

    for cpe in cpe_match:
        cpe_uri = cpe['cpe23Uri']

        cpe_pieces = cpe_uri.split(':')
        part_list.append(cpe_pieces[2])
        vendor_list.append(cpe_pieces[3])
        product_list.append(cpe_pieces[4])

    return part_list, vendor_list, product_list


def main(cve_json_feed, cves_output_file, year_begin, year_end):
    print('Preparing output folder...')

    # create output folder if it doesnt exists
    dirs = os.path.split(cves_output_file)[0]
    if not os.path.exists(dirs):
        os.makedirs(dirs)

    # delete output file if it exists
    if os.path.exists(cves_output_file):
        os.remove(cves_output_file)

    cves = list()

    for year in range(year_begin, year_end):

        cve_json = None

        print(f'CVE feed from year {year}')
        print('  - Downloading feed...')

        try:
            with urlopen(cve_json_feed.format(year)) as response:
                with GzipFile(fileobj=response) as uncompressed:
                    cve_json = json.loads(uncompressed.read())
        except Exception as e:
            print(f'Could not download json file: {e}')

        print('  - Parsing feed...')

        for cve in cve_json['CVE_Items']:
            cve_entry = dict()

            cve_entry.setdefault('ID', cve['cve']['CVE_data_meta']['ID'])

            cwe_list = list()
            for problem_type in cve['cve']['problemtype']['problemtype_data']:
                for cwe in problem_type['description']:
                    cwe_list.append(cwe['value'])

            cve_entry.setdefault('cwe',  list(set(cwe_list)) if cwe_list else [])

            cvss = None
            cvss_type = ''
            if 'baseMetricV3' in cve['impact']:
                cvss = cve['impact']['baseMetricV3']
                cvss_type = '3'
            elif 'baseMetricV2' in cve['impact']:
                cvss = cve['impact']['baseMetricV2']
                cvss_type = '2'

            cpe_part_list = list()
            vendor_list = list()
            product_list = list()

            for node in cve['configurations']['nodes']:
                if node['operator'] == 'AND':
                    if 'children' in node.keys():
                        cpe_part_list, vendor_list, product_list = extract_and(node['children'])
                    elif 'cpe_match' in node.keys():
                        cpe_part_list, vendor_list, product_list = extract_or(node['cpe_match'])
                elif node['operator'] == 'OR' and 'cpe_match' in node.keys():
                    cpe_part_list, vendor_list, product_list = extract_or(node['cpe_match'])

            cve_entry.setdefault('part', list(set(cpe_part_list)) if cpe_part_list else [])
            cve_entry.setdefault('vendor', list(set(vendor_list)) if vendor_list else [])
            cve_entry.setdefault('product', list(set(product_list)) if product_list else [])

            # retrieving cvssV3 info
            if cvss_type == '3':
                cve_entry.setdefault('attackVector', cvss['cvssV3']['attackVector'])
                cve_entry.setdefault('attackComplexity', cvss['cvssV3']['attackComplexity'])
                cve_entry.setdefault('privilegesRequired', cvss['cvssV3']['privilegesRequired'])
                cve_entry.setdefault('userInteraction', cvss['cvssV3']['userInteraction'])
                cve_entry.setdefault('scope', cvss['cvssV3']['scope'])
                cve_entry.setdefault(
                    'confidentialityImpact', cvss['cvssV3']['confidentialityImpact'])
                cve_entry.setdefault('integrityImpact', cvss['cvssV3']['integrityImpact'])
                cve_entry.setdefault('availabilityImpact', cvss['cvssV3']['availabilityImpact'])
                cve_entry.setdefault('baseScore', cvss['cvssV3']['baseScore'])
                cve_entry.setdefault('baseSeverity', cvss['cvssV3']['baseSeverity'])

                cve_entry.setdefault('exploitabilityScore', cvss['exploitabilityScore'])
                cve_entry.setdefault('impactScore', cvss['impactScore'])

            # retrieving cvssV2 info
            elif cvss_type == '2':
                cve_entry.setdefault('attackVector', cvss['cvssV2']['accessVector'])
                cve_entry.setdefault('attackComplexity', cvss['cvssV2']['accessComplexity'])
                cve_entry.setdefault('privilegesRequired', cvss['cvssV2']['authentication'])

                ui = 'N/A'
                if 'userInteractionRequired' in cvss:
                    ui = 'Required' if bool(cvss['userInteractionRequired']) else 'None'
                cve_entry.setdefault('userInteraction', ui)

                cve_entry.setdefault('scope', 'N/A')
                cve_entry.setdefault(
                    'confidentialityImpact', cvss['cvssV2']['confidentialityImpact'])
                cve_entry.setdefault('integrityImpact', cvss['cvssV2']['integrityImpact'])
                cve_entry.setdefault('availabilityImpact', cvss['cvssV2']['availabilityImpact'])
                cve_entry.setdefault('baseScore', cvss['cvssV2']['baseScore'])
                cve_entry.setdefault('baseSeverity', cvss['severity'])

                cve_entry.setdefault('exploitabilityScore', cvss['exploitabilityScore'])
                cve_entry.setdefault('impactScore', cvss['impactScore'])
            else:
                cve_entry.setdefault('attackVector', 'N/A')
                cve_entry.setdefault('attackComplexity', 'N/A')
                cve_entry.setdefault('privilegesRequired', 'N/A')
                cve_entry.setdefault('userInteraction', 'N/A')
                cve_entry.setdefault('scope', 'N/A')
                cve_entry.setdefault('confidentialityImpact', 'N/A')
                cve_entry.setdefault('integrityImpact', 'N/A')
                cve_entry.setdefault('availabilityImpact', 'N/A')
                cve_entry.setdefault('baseScore', 'N/A')
                cve_entry.setdefault('baseSeverity', 'N/A')

                cve_entry.setdefault('exploitabilityScore', 'N/A')
                cve_entry.setdefault('impactScore', 'N/A')

            cve_entry.setdefault('cvssType', cvss_type)
            cve_entry.setdefault('publishedDate', cve['publishedDate'][:10])
            cve_entry.setdefault('lastModifiedDate', cve['lastModifiedDate'][:10])

            keys = ['ID', 'cwe', 'part', 'vendor', 'product', 'attackVector', 'attackComplexity',
                    'privilegesRequired', 'userInteraction', 'confidentialityImpact',
                    'integrityImpact', 'availabilityImpact', 'baseScore', 'exploitabilityScore',
                    'impactScore', 'cvssType', 'publishedDate', 'lastModifiedDate']

            for item in keys:
                if item not in cve_entry.keys():
                    cve_entry.setdefault(item, 'N/A')

            cves.append(cve_entry)

    with open(cves_output_file, 'a') as f:
        json.dump(cves, f, indent=4)

    print('Done!')


if __name__ == '__main__':

    main(cve_json_feed='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz',
         cves_output_file='datasets/cves_info.json',
         year_begin=2002,
         year_end=2022)
