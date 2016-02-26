import requests
import time
import json

CONTROLLER_API_URL = 'http://52.37.66.79:8080'


def _url(path, model_name='beacon'):
        """Private method used to build api urls"""
        return '/'.join(s.strip('/') for s in [
            CONTROLLER_API_URL,
            "".join([model_name, 'modelview']),
            'api', path])


def _get(url):
    try:
        return requests.get(url).json()
    except requests.ConnectionError:
        print """Error: Unable to connect to Controller.
            Trying again in 5 seconds."""
        time.sleep(5)


def _post(url, data):
    try:
        return requests.post(url, data)
    except requests.ConnectionError:
        print """Error: Unable to connect to Controller.
            Trying again in 5 seconds."""
        time.sleep(5)


def remove_task(implant_uuid, task_id):
    """Remove the implant task from the controller"""
    data = {
        'implant_uuid': implant_uuid,
        'task_id': task_id
    }
    data_json = json.dumps(data)
    return _post(_url('/removetask', model_name='implant'), data=data_json)


def get_beacon_filters():
    """Return a dict of Beacons"""
    return _get(_url('/read'))


def get_implants():
    """Return a dict of Tasks"""
    return _get(_url('/read', model_name='implant'))


def send_beacon(beacon):
    return _post(
        _url('/postbeacon', model_name='beacon'), data=beacon.toJson())


def send_log(message, message_type="Info"):
    data = {
        'message_type': message_type,
        'message': message
    }
    return _post(_url('/postlog', model_name='log'), data=json.dumps(data))
