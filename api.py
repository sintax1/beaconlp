import requests
import time

CONTROLLER_API_URL = 'http://172.16.201.245:8080'


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


def get_beacon_filters():
    """Return a dict of Beacons"""
    return _get(_url('/read'))


def get_implants():
    """Return a dict of Tasks"""
    return _get(_url('/read', model_name='implant'))


def send_beacon(beacon):
    return _post(_url('/process', model_name='beacon'), data=beacon.toJson())
