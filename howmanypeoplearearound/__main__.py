import threading
import sys
import os
import os.path
import platform
import subprocess
import json
import time

import argparse
import base64
import datetime

import netifaces
import click

from google.api_core import retry
import jwt
import requests

from howmanypeoplearearound.oui import load_dictionary, download_oui
from howmanypeoplearearound.analysis import analyze_file
from howmanypeoplearearound.colors import *

if os.name != 'nt':
    from pick import pick

_BASE_URL = 'https://cloudiotdevice.googleapis.com/v1'
_BACKOFF_DURATION = 60

# [START iot_http_jwt]


def create_jwt(project_id, private_key_file, algorithm):
    token = {
        # The time the token was issued.
        'iat': datetime.datetime.utcnow(),
        # Token expiration time.
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        # The audience field should always be set to the GCP project id.
        'aud': project_id
    }

    # Read the private key file.
    with open(private_key_file, 'r') as f:
        private_key = f.read()

    print('Creating JWT using {} from private key file {}'.format(
        algorithm, private_key_file))

    return jwt.encode(token, private_key, algorithm=algorithm).decode('ascii')
# [END iot_http_jwt]


@retry.Retry(
    predicate=retry.if_exception_type(AssertionError),
    deadline=_BACKOFF_DURATION)
# [START iot_http_publish]
def publish_message(
        message, message_type, base_url, project_id, cloud_region, registry_id,
        device_id, jwt_token):
    headers = {
        'authorization': 'Bearer {}'.format(jwt_token),
        'content-type': 'application/json',
        'cache-control': 'no-cache'
    }

    # Publish to the events or state topic based on the flag.
    url_suffix = 'publishEvent' if message_type == 'event' else 'setState'

    publish_url = (
        '{}/projects/{}/locations/{}/registries/{}/devices/{}:{}').format(
            base_url, project_id, cloud_region, registry_id, device_id,
            url_suffix)

    body = None
    msg_bytes = base64.urlsafe_b64encode(message.encode('utf-8'))
    if message_type == 'event':
        body = {'binary_data': msg_bytes.decode('ascii')}
    else:
        body = {
            'state': {'binary_data': msg_bytes.decode('ascii')}
        }

    resp = requests.post(
        publish_url, data=json.dumps(body), headers=headers)

    if (resp.status_code != 200):
        print('Response came back {}, retrying'.format(resp.status_code))
        raise AssertionError('Not OK response: {}'.format(resp.status_code))

    return resp
# [END iot_http_publish]


@retry.Retry(
    predicate=retry.if_exception_type(AssertionError),
    deadline=_BACKOFF_DURATION)
# [START iot_http_getconfig]
def get_config(
        version, message_type, base_url, project_id, cloud_region, registry_id,
        device_id, jwt_token):
    headers = {
        'authorization': 'Bearer {}'.format(jwt_token),
        'content-type': 'application/json',
        'cache-control': 'no-cache'
    }

    basepath = '{}/projects/{}/locations/{}/registries/{}/devices/{}/'
    template = basepath + 'config?local_version={}'
    config_url = template.format(
        base_url, project_id, cloud_region, registry_id, device_id, version)

    resp = requests.get(config_url, headers=headers)

    if (resp.status_code != 200):
        print('Error getting config: {}, retrying'.format(resp.status_code))
        raise AssertionError('Not OK response: {}'.format(resp.status_code))

    return resp
# [END iot_http_getconfig]

# [START iot_http_run]


def sendIoTCore(num_people, project_id, registry_id, device_id, private_key_file, algorithm, cloud_region, ca_certs, num_messages, message_type, base_url, jwt_expires_minutes):

    jwt_token = create_jwt(
        project_id, private_key_file, algorithm)
    jwt_iat = datetime.datetime.utcnow()
    jwt_exp_mins = jwt_expires_minutes

    print('Latest configuration: {}'.format(get_config(
        '0', message_type, base_url, project_id,
        cloud_region, registry_id, device_id, jwt_token).text))

    # Publish num_messages mesages to the HTTP bridge once per second.
    # for i in range(1, num_messages + 1):
    seconds_since_issue = (datetime.datetime.utcnow() - jwt_iat).seconds
    if seconds_since_issue > 60 * jwt_exp_mins:
        print('Refreshing token after {}s').format(seconds_since_issue)
        jwt_token = create_jwt(
            project_id, private_key_file, algorithm)
        jwt_iat = datetime.datetime.utcnow()

    # payload = '{}/{}-payload-{}'.format(
    #     registry_id, device_id, num_people)

    payload = {
        'sensorId': device_id,
        # scanTimestamp: n,
        'scanTimestamp': '2019-09-03 07:53:34.490 UTC',
        'rssi':  num_people,
        'deviceId': num_people
    }

    jsonpayload = json.dumps(payload)

    # print('Publishing message {}/{}: \'{}\''.format(
    # i, num_messages, payload))
    print('Publishing message {}: \'{}\''.format(num_messages, payload))
    print('Publishing message {}: \'{}\''.format(num_messages, jsonpayload))

    resp = publish_message(
        payload, message_type, base_url, project_id,
        cloud_region, registry_id, device_id, jwt_token)

    print('HTTP response: ', resp)

    # Send events every second. State should not be updated as often
    # time.sleep(1 if message_type == 'event' else 5)
    print('Finished.')
# [END iot_http_run]


def which(program):
    """Determines whether program exists
    """
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    raise


def showTimer(timeleft):
    """Shows a countdown timer"""
    total = int(timeleft) * 10
    for i in range(total):
        sys.stdout.write('\r')
        # the exact output you're looking for:
        timeleft_string = '%ds left' % int((total - i + 1) / 10)
        if (total - i + 1) > 600:
            timeleft_string = '%dmin %ds left' % (
                int((total - i + 1) / 600), int((total - i + 1) / 10 % 60))
        sys.stdout.write("[%-50s] %d%% %15s" %
                         ('=' * int(50.5 * i / total), 101 * i / total, timeleft_string))
        sys.stdout.flush()
        time.sleep(0.1)
    print("")


def fileToMacSet(path):
    with open(path, 'r') as f:
        maclist = f.readlines()
    return set([x.strip() for x in maclist])


@click.command()
@click.option('-a', '--adapter', default='', help='adapter to use')
@click.option('-z', '--analyze', default='', help='analyze file')
@click.option('-s', '--scantime', default='60', help='time in seconds to scan')
@click.option('-o', '--out', default='', help='output cellphone data to file')
@click.option('-d', '--dictionary', default='oui.txt', help='OUI dictionary')
@click.option('-v', '--verbose', help='verbose mode', is_flag=True)
@click.option('--number', help='just print the number', is_flag=True)
@click.option('-j', '--jsonprint', help='print JSON of cellphone data', is_flag=True)
@click.option('-n', '--nearby', help='only quantify signals that are nearby (rssi > -70)', is_flag=True)
@click.option('--allmacaddresses', help='do not check MAC addresses against the OUI database to only recognize known cellphone manufacturers', is_flag=True)  # noqa
@click.option('--nocorrection', help='do not apply correction', is_flag=True)
@click.option('--loop', help='loop forever', is_flag=True)
@click.option('--port', default=8001, help='port to use when serving analysis')
@click.option('--sort', help='sort cellphone data by distance (rssi)', is_flag=True)
@click.option('--targetmacs', help='read a file that contains target MAC addresses', default='')
@click.option('-f', '--pcap', help='read a pcap file instead of capturing')
@click.option('--project_id', default='partner-summit-2019', help='GCP cloud project name')
@click.option('--registry_id', default='pi-registry', help='Cloud IoT Core registry id')
@click.option('--device_id', default='pi1', help='Cloud IoT Core device id')
@click.option('--private_key_file', default='../rsa_private.pem', help='Path to private key file.')
@click.option('--algorithm', default='RS256', help='The encryption algorithm to use to generate the JWT.')
@click.option('--cloud_region', default='asia-east1', help='GCP cloud region')
@click.option('--ca_certs', default='roots.pem', help='CA root from https://pki.google.com/roots.pem')
@click.option('--num_messages', type=int, default=100, help='Number of messages to publish.')
@click.option('--message_type', default='event', help='telemetry event or a device state message.')
@click.option('--base_url', default=_BASE_URL, help='Base URL for the Cloud IoT Core Device Service API')
@click.option('--jwt_expires_minutes', type=int, default=20, help='Expiration time, in minutes, for JWT tokens.')
def main(adapter, scantime, verbose, dictionary, number, nearby, jsonprint, out, allmacaddresses, nocorrection, loop, analyze, port, sort, targetmacs, pcap, project_id, registry_id, device_id, private_key_file, algorithm, cloud_region, ca_certs, num_messages, message_type, base_url, jwt_expires_minutes):
    if analyze != '':
        analyze_file(analyze, port)
        return
    if loop:
        while True:
            adapter = scan(adapter, scantime, verbose, dictionary, number,
                           nearby, jsonprint, out, allmacaddresses, nocorrection, loop, sort, targetmacs, pcap,
                           project_id, registry_id, device_id, private_key_file, algorithm, cloud_region, ca_certs, num_messages, message_type, base_url, jwt_expires_minutes)
    else:
        scan(adapter, scantime, verbose, dictionary, number,
             nearby, jsonprint, out, allmacaddresses, nocorrection, loop, sort, targetmacs, pcap,
             project_id, registry_id, device_id, private_key_file, algorithm, cloud_region, ca_certs, num_messages, message_type, base_url, jwt_expires_minutes)


def scan(adapter, scantime, verbose, dictionary, number, nearby, jsonprint, out, allmacaddresses, nocorrection, loop, sort, targetmacs, pcap, project_id, registry_id, device_id, private_key_file, algorithm, cloud_region, ca_certs, num_messages, message_type, base_url, jwt_expires_minutes):
    """Monitor wifi signals to count the number of people around you"""

    # print("OS: " + os.name)
    # print("Platform: " + platform.system())

    if (not os.path.isfile(dictionary)) or (not os.access(dictionary, os.R_OK)):
        download_oui(dictionary)

    oui = load_dictionary(dictionary)

    if not oui:
        print('couldn\'t load [%s]' % dictionary)
        sys.exit(1)

    try:
        tshark = which("tshark")
    except:
        if platform.system() != 'Darwin':
            print('tshark not found, install using\n\napt-get install tshark\n')
        else:
            print('wireshark not found, install using: \n\tbrew install wireshark')
            print(
                'you may also need to execute: \n\tbrew cask install wireshark-chmodbpf')
        sys.exit(1)

    if jsonprint:
        number = True
    if number:
        verbose = False

    if not pcap:
        if len(adapter) == 0:
            if os.name == 'nt':
                print('You must specify the adapter with   -a ADAPTER')
                print('Choose from the following: ' +
                      ', '.join(netifaces.interfaces()))
                sys.exit(1)
            title = 'Please choose the adapter you want to use: '
            adapter, index = pick(netifaces.interfaces(), title)

        print("Using %s adapter and scanning for %s seconds..." %
              (adapter, scantime))

        if not number:
            # Start timer
            t1 = threading.Thread(target=showTimer, args=(scantime,))
            t1.daemon = True
            t1.start()

        dump_file = '/tmp/tshark-temp'
        # Scan with tshark
        command = [tshark, '-i', adapter, '-a',
                   'duration:' + scantime, '-w', dump_file]
        if verbose:
            print(' '.join(command))
        run_tshark = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, nothing = run_tshark.communicate()

        if not number:
            t1.join()
    else:
        dump_file = pcap

    # Read tshark output
    command = [
        tshark, '-r',
        dump_file, '-T',
        'fields', '-e',
        'wlan.sa', '-e',
        'wlan.bssid', '-e',
        'radiotap.dbm_antsignal'
    ]
    if verbose:
        print(' '.join(command))
    run_tshark = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, nothing = run_tshark.communicate()

    # read target MAC address
    targetmacset = set()
    if targetmacs != '':
        targetmacset = fileToMacSet(targetmacs)

    foundMacs = {}
    for line in output.decode('utf-8').split('\n'):
        if verbose:
            print(line)
        if line.strip() == '':
            continue
        mac = line.split()[0].strip().split(',')[0]
        dats = line.split()
        if len(dats) == 3:
            if ':' not in dats[0] or len(dats) != 3:
                continue
            if mac not in foundMacs:
                foundMacs[mac] = []
            dats_2_split = dats[2].split(',')
            if len(dats_2_split) > 1:
                rssi = float(dats_2_split[0]) / 2 + float(dats_2_split[1]) / 2
            else:
                rssi = float(dats_2_split[0])
            foundMacs[mac].append(rssi)

    if not foundMacs:
        print("Found no signals, are you sure %s supports monitor mode?" % adapter)
        sys.exit(1)

    for key, value in foundMacs.items():
        foundMacs[key] = float(sum(value)) / float(len(value))

    # Find target MAC address in foundMacs
    if targetmacset:
        sys.stdout.write(RED)
        for mac in foundMacs:
            if mac in targetmacset:
                print("Found MAC address: %s" % mac)
                print("rssi: %s" % str(foundMacs[mac]))
        sys.stdout.write(RESET)

    cellphone = [
        'Motorola Mobility LLC, a Lenovo Company',
        'GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD',
        'Huawei Symantec Technologies Co.,Ltd.',
        'Microsoft',
        'HTC Corporation',
        'Samsung Electronics Co.,Ltd',
        'SAMSUNG ELECTRO-MECHANICS(THAILAND)',
        'BlackBerry RTS',
        'LG ELECTRONICS INC',
        'Apple, Inc.',
        'LG Electronics',
        'OnePlus Tech (Shenzhen) Ltd',
        'Xiaomi Communications Co Ltd',
        'LG Electronics (Mobile Communications)']

    cellphone_people = []
    for mac in foundMacs:
        oui_id = 'Not in OUI'
        if mac[:8] in oui:
            oui_id = oui[mac[:8]]
        if verbose:
            print(mac, oui_id, oui_id in cellphone)
        if allmacaddresses or oui_id in cellphone:
            if not nearby or (nearby and foundMacs[mac] > -70):
                cellphone_people.append(
                    {'company': oui_id, 'rssi': foundMacs[mac], 'mac': mac})
    if sort:
        cellphone_people.sort(key=lambda x: x['rssi'], reverse=True)
    if verbose:
        print(json.dumps(cellphone_people, indent=2))

    # US / Canada: https://twitter.com/conradhackett/status/701798230619590656
    percentage_of_people_with_phones = 0.7
    if nocorrection:
        percentage_of_people_with_phones = 1
    num_people = int(round(len(cellphone_people) /
                           percentage_of_people_with_phones))

    if number and not jsonprint:
        print(num_people)
    elif jsonprint:
        print(json.dumps(cellphone_people, indent=2))
    else:
        if num_people == 0:
            print("No one around (not even you!).")
        elif num_people == 1:
            print("No one around, but you.")
        else:
            print("There are about %d people around." % num_people)
            sendIoTCore(num_people, project_id, registry_id, device_id, private_key_file, algorithm,
                        cloud_region, ca_certs, num_messages, message_type, base_url, jwt_expires_minutes)
    if out:
        with open(out, 'a') as f:
            data_dump = {'cellphones': cellphone_people, 'time': time.time()}
            f.write(json.dumps(data_dump) + "\n")
        if verbose:
            print("Wrote %d records to %s" % (len(cellphone_people), out))
    if not pcap:
        os.remove(dump_file)
    return adapter


if __name__ == '__main__':
    main()
