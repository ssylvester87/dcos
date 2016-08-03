import requests


class CAClient:
    def __init__(self, base_url, headers={}, CA_certificate_filename=None):
        self.base_url = base_url
        self.default_headers = {'Accept': 'application/json', 'Accept-Charset': 'utf-8'}
        self.default_headers.update(headers)
        self.CA_certificate_filename = CA_certificate_filename

    def sign(self, csr):
        url = self.base_url + '/ca/api/v2/sign'
        headers = self.default_headers.copy()

        # no hosts in data means CSR must contain SANs
        data = {
            'certificate_request': csr,
            'profile': '',
            'crl_override': '',
            'label': ''
        }

        r = requests.post(url, headers=headers, json=data, verify=self.CA_certificate_filename)

        if r.status_code != 200:
            raise Exception('sign certificate failed: status {code}. Reason: {reason}. Output: {text}'.format(
                code=r.status_code,
                reason=r.reason,
                text=r.text))

        return r.json()['result']['certificate'].strip() + '\n'
