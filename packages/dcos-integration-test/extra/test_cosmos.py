def test_if_we_have_capabilities(peter_api_session):
    headers = {'Accept': 'application/vnd.dcos.capabilities+json;charset=utf-8;version=v1'}
    r = peter_api_session.get('capabilities', headers=headers)
    assert r.status_code == 200
    assert {'name': 'PACKAGE_MANAGEMENT'} in r.json()['capabilities']
