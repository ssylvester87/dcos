import json
import logging
import uuid

import requests

from test_util.marathon import get_test_app
from test_util.recordio import Decoder, Encoder


def test_if_marathon_app_can_be_debugged(cluster):
    def post(url, headers, json=None, data=None, stream=False):
        r = requests.post(url, headers=headers, json=json, data=data, stream=stream)
        logging.info(
            'Got %s with POST request to %s with headers %s and json data %s.',
            r.status_code,
            url,
            headers,
            json
        )
        assert r.status_code == 200
        return r

    def find_container_id(state, app_id):
        container_id = None
        for framework in state['frameworks']:
            for task in framework['tasks']:
                if app_id in task['id']:
                    container_id = task['statuses'][0]['container_status']['container_id']['value']
        if container_id is None:
            raise Exception('Container ID not found in task status report for instance of app_id {}'.format(app_id))
        return container_id

    def find_agent_id(state, app_id):
        agent_id = None
        for framework in state['frameworks']:
            for task in framework['tasks']:
                if app_id in task['id']:
                    agent_id = task['slave_id']
        if agent_id is None:
            raise Exception('Agent ID not found for instance of app_id {}'.format(app_id))
        return agent_id

    def find_agent_hostname(state, agent_id):
        agent_hostname = None
        for agent in state['slaves']:
            if agent['id'] == agent_id:
                agent_hostname = agent['hostname']
        if agent_hostname is None:
            raise Exception('Agent hostname not found for agent_id {}'.format(agent_id))
        return agent_hostname_

    # Creates and yields the initial ATTACH_CONTAINER_INPUT message, then a data message,
    # then an empty data chunk to indicate end-of-stream.
    def _input_streamer(encoder, nested_container_id, input_data):
        message = {
            'type': 'ATTACH_CONTAINER_INPUT',
            'attach_container_input': {
                'type': 'CONTAINER_ID',
                'container_id': nested_container_id}}
        yield encoder.encode(message)

        message = {
            'type': 'ATTACH_CONTAINER_INPUT',
            'attach_container_input': {
                'type': 'PROCESS_IO',
                'process_io': {
                    'type': 'DATA',
                    'data': {
                        'type': 'STDIN',
                        'data': input_data}}}}
        yield encoder.encode(message)

        # Place an empty string to indicate EOF to the server and push
        # 'None' to our queue to indicate that we are done processing input.
        message['attach_container_input']['process_io']['data']['data'] = ''
        yield encoder.encode(message)

    # Launch a basic marathon app (no image), so we can debug into it!
    app, test_uuid = get_test_app()
    test_app_id = 'integration-test-{}'.format(test_uuid)
    cluster.marathon.deploy_app(app)

    # Fetch the mesos master state once the task is running
    master_state_url = 'http://{}:{}/state'.format(cluster.masters[0], 5050)
    r = requests.get(master_state_url)
    logging.debug('Got %s with request for %s. Response: \n%s', r.status_code, master_state_url, r.text)
    assert r.status_code == 200
    state = r.json()

    # Find the agent_id and container_id from master state
    container_id = find_container_id(state, test_app_id)
    agent_id = find_agent_id(state, test_app_id)
    agent_hostname = find_agent_hostname(state, agent_id)
    agent_v1_url = 'http://{}:{}/api/v1'.format(agent_hostname, 5051)
    logging.debug('Located %s with containerID %s on agent %s', test_app_id, container_id, agent_hostname)

    # Prepare nested container id data
    nested_container_id = {
        'value': 'debug-%s' % str(uuid.uuid4()),
        'parent': {'value': '%s' % container_id}}

    # Launch debug session and attach to output stream of debug container
    output_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json+recordio',
        'Connection': 'keep-alive'
    }
    lncs_data = {
        'type': 'LAUNCH_NESTED_CONTAINER_SESSION',
        'launch_nested_container_session': {
            'command': {'value': 'cat'},
            'container_id': nested_container_id}}
    launch_output = post(agent_v1_url, output_headers, json=lncs_data, stream=True)

    # Attach to output stream of nested container
    attach_out_data = {
        'type': 'ATTACH_CONTAINER_OUTPUT',
        'attach_container_output': {'container_id': nested_container_id}}
    attached_output = post(agent_v1_url, output_headers, json=attach_out_data, stream=True)

    # Attach to input stream of debug container and stream a message
    input_headers = {
        'Content-Type': 'application/json+recordio',
        'Accept': 'application/json',
        'Connection': 'keep-alive',
        'Transfer-Encoding': 'chunked'
    }
    encoder = Encoder(lambda s: bytes(json.dumps(s, ensure_ascii=False), "UTF-8"))
    post(agent_v1_url, input_headers, data=_input_streamer(encoder, nested_container_id, 'meow'))

    # Verify the streamed output from the launch session
    decoder = Decoder(lambda s: json.loads(s.decode("UTF-8")))
    for chunk in launch_output.iter_content():
        for r in decoder.decode(chunk):
            if r['type'] == 'DATA':
                logging.debug('Extracted data chunk: %s', r['data'])
                assert r['data']['data'] == 'meow', 'Output did not match expected'

    # Verify the message from the attached output stream
    for chunk in attached_output.iter_content():
        for r in decoder.decode(chunk):
            if r['type'] == 'DATA':
                logging.debug('Extracted data chunk: %s', r['data'])
                assert r['data']['data'] == 'meow', 'Output did not match expected'

    # Destroy the app and the task's containers now that we're done with it
    cluster.marathon.destroy_app(test_app_id)
