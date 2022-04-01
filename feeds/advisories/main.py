
# local imports
from microsoft import download_adv as microsoft_adv
from intel import download_adv as intel_adv
from adobe import download_adv as adobe_adv


def main():
    print('Download Microsoft advisory...')
    microsoft_adv(base_url='https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/',
                  advisory_csv='output/microsoft_advisory.csv',
                  year_begin=2017,
                  year_end=2022)

    print('\nDownload Intel advisory...')
    intel_adv(base_url='https://www.intel.com',
              security_center_url='content/www/us/en/security-center/default.html',
              advisory_csv='output/intel_advisory.csv')

    print('\nDownload Adobe advisory...')
    adobe_adv(base_url='https://helpx.adobe.com',
              security_bulletin='security/security-bulletin.html',
              advisory_csv='output/adobe_advisory.csv')


if __name__ == '__main__':
    main()
