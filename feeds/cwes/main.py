# python imports
import zipfile
from io import BytesIO
from urllib.request import urlopen
from urllib.parse import urljoin

# project imports
from commons.file import mkdir, rm
from commons.parse import request_clean_page


def main(cwe_feed, mitre_csv, owasp_csv, mitre_id, owasp_id):

    soup = request_clean_page(cwe_feed)

    ids = [mitre_id, owasp_id]
    outputs = [mitre_csv, owasp_csv]

    print('Downloading files...')

    for id, output in zip(ids, outputs):
        # create output folder
        # if it doesnt exists
        mkdir(output)

        # delete output file
        # if it exists
        rm(output)

        try:
            feed = soup.find('tr', {'id': f'cwe{id}'}).find('a', string='CSV.zip')
            url = urljoin('https://cwe.mitre.org', feed.get('href'))

            with urlopen(url) as response:
                with zipfile.ZipFile(BytesIO(response.read())) as uncompressed:
                    with open(output, 'wb') as f:
                        f.write(uncompressed.read(f'{id}.csv'))
        except Exception as e:
            print(f'Could not download file: {e}')


if __name__ == '__main__':
    main(cwe_feed='https://cwe.mitre.org/data/downloads.html',
         mitre_csv='output/cwe_top_25.csv',
         owasp_csv='output/owasp_top_10.csv',
         mitre_id='1337',
         owasp_id='1344')
