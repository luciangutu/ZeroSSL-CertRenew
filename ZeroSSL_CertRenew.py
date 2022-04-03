import requests
import subprocess
import json
from urllib3.exceptions import InsecureRequestWarning
from pathlib import Path
import time
import shutil
import argparse

# Suppress https warning (Burp)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class SSLCertReNew(object):

    def __init__(self, apiKey, domain):
        self.CertPath = None
        self.HttpContent = None
        self.HttpUrl = None
        self.certHash = None
        self.url = 'https://api.zerossl.com'
        # self.proxies = { 'http' : 'http://127.0.0.1:8080', 'https' : 'http://127.0.0.1:8080' } # for testing purposes with Burp
        self.proxies = None
        self.apiKey = apiKey
        self.certificateDomain = domain
        self.csr = self.createCsr()

    def createCsr(self):
        req = f'''[ req ]
default_bits = 2048
prompt = no
encrypt_key = no
default_md = sha256 
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = {self.certificateDomain}
emailAddress = postmaster@{self.certificateDomain}
O = Non Profit
OU = Climb
L = Bucharest
ST = Bucharest
C = RO

[ req_ext ]
subjectAltName = DNS: www.{self.certificateDomain}, DNS: {self.certificateDomain}
'''

        # save file domain.conf
        # create blank file
        with open(f'{self.certificateDomain}.conf', 'w+') as f:
            f.write(req)
        process = subprocess.Popen(['openssl', 'req', '-new', '-config', f'{self.certificateDomain}.conf', '-keyout',
                                    f'{self.certificateDomain}_key.pem', '-out', f'{self.certificateDomain}.csr'])
        process.wait()
        # read csr
        with open(f'{self.certificateDomain}.csr', 'r') as file:
            data = file.read().replace('\n', '')
        return data

    def InitialRequest(self):
        response = requests.post(self.url + f'/certificates?access_key={self.apiKey}',
                                 proxies=self.proxies,
                                 data={'certificate_domains': self.certificateDomain,
                                       'certificate_validity_days': 90,
                                       'certificate_csr': self.csr}
                                 )
        result = json.loads(response.text)
        print()
        print(f'Request Result: {result}')

        self.certHash = result['id']
        # url from json
        self.HttpUrl = result['validation']['other_methods'][f'{self.certificateDomain}']['file_validation_url_http']
        self.HttpContent = result['validation']['other_methods'][f'{self.certificateDomain}'][
            'file_validation_content']
        dirOne = self.HttpUrl.split('/')[-3]
        dirTwo = self.HttpUrl.split('/')[-2]
        fileName = self.HttpUrl.split('/')[-1]

        DocumentRoot = f'/var/www/{self.certificateDomain}/web'
        self.CertPath = f'/var/www/{self.certificateDomain}/ssl'

        # handle the symlinks (if any)
        if Path(f'{DocumentRoot}').is_symlink():
            DocumentRoot = Path(f'{DocumentRoot}').resolve()
            self.CertPath = f'{DocumentRoot}/ssl'

        # create directories for validation
        Path(f'{DocumentRoot}/{dirOne}/{dirTwo}').mkdir(parents=True, exist_ok=True)
        # save file
        # convert array into string with newline
        string = '\n'.join(
            result['validation']['other_methods'][f'{self.certificateDomain}']['file_validation_content'])
        with open(f'{DocumentRoot}/{dirOne}/{dirTwo}/{fileName}', 'w') as f:
            f.write(string)

    def VerificationMethods(self):
        """
        Ask ZeroSSL to use HTTP validation method
        """
        response = requests.post(self.url + f'/certificates/{self.certHash}/challenges?access_key={self.apiKey}',
                                 proxies=self.proxies, data={'validation_method': 'HTTP_CSR_HASH'})
        result = json.loads(response.text)
        print()
        print(f'Verification Result: {result}')

    def VerificationStatus(self):
        response = requests.get(self.url + f'/certificates/{self.certHash}/status?access_key={self.apiKey}',
                                proxies=self.proxies)
        result = json.loads(response.text)
        print()
        print(f'Verification Status: {result}')
        return result['validation_completed']

    def ListCertificates(self, certificate_status="issued"):
        response = requests.get(self.url + f'/certificates?access_key={self.apiKey}&certificate_status='
                                           f'{certificate_status}&search={self.certificateDomain}',
                                proxies=self.proxies)
        result = json.loads(response.text)
        return result

    def DownloadAndSave(self):
        response = requests.get(self.url + f'/certificates/{self.certHash}/download/return?access_key={self.apiKey}')
        result = json.loads(response.text)
        print()
        print(f'Certificate: {result}')
        ca_bundle = result['ca_bundle.crt']
        cert = result['certificate.crt']

        with open(f'{self.CertPath}/{self.certificateDomain}_cert.pem', 'w+') as f:
            f.write(cert)

        with open(f'{self.CertPath}/{self.certificateDomain}_ca.pem', 'w+') as f:
            f.write(ca_bundle)

        # move private key
        shutil.move(f'{self.certificateDomain}_key.pem', f'{self.CertPath}/{self.certificateDomain}_key.pem')


def parse_args():
    """
    Parsing the command line arguments
    """
    parser = argparse.ArgumentParser(description='Renew ZeroSSL certificate')
    parser.add_argument("-d", "--Domains", help="Domain list separated by comma: aaa.com,bbb.com", required=True)
    parser.add_argument("-k", "--ApiKey", help="The ZeroSSL Developer ApiKey (https://app.zerossl.com/developer)",
                        required=True)
    args = parser.parse_args()
    if args.Domains:
        _domains = args.Domains.split(",")
    else:
        # this should not happen
        _domains = []
    if args.ApiKey:
        _api_key = args.ApiKey
    else:
        # this should not happen
        _api_key = None
    return _domains, _api_key


def main():
    domains, api_key = parse_args()

    for domain in domains:
        obj = SSLCertReNew(api_key, domain)
        # if the cert is expired for domain, just renew it

        # run steps for creating new cert
        obj.InitialRequest()
        obj.VerificationMethods()
        # check validation status
        while obj.VerificationStatus() == 0:
            time.sleep(10)
            obj.VerificationStatus()
        time.sleep(5)
        obj.DownloadAndSave()


if __name__ == "__main__":
    main()
