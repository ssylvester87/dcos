import requests

from dcos_internal_utils import DCOS_CA_TRUST_BUNDLE_FILE_PATH


class CAClient:
    def __init__(self, base_url, headers={}):
        self.base_url = base_url
        self.default_headers = {'Accept': 'application/json', 'Accept-Charset': 'utf-8'}
        self.default_headers.update(headers)

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

        r = requests.post(
            url,
            headers=headers,
            json=data,
            verify=DCOS_CA_TRUST_BUNDLE_FILE_PATH)

        if r.status_code != 200:
            raise Exception('sign certificate failed: status {code}. Reason: {reason}. Output: {text}'.format(
                code=r.status_code,
                reason=r.reason,
                text=r.text))

        return r.json()['result']['certificate'].strip() + '\n'
