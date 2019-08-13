import os
import datetime
import binascii
import json
import argparse
import hid
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sim_hid_device import SimMchpAwsZTHidDevice
from aws_kit_common import *

import re
import binascii
import json

DEVICE_HID_VID = 0x04d8
DEVICE_HID_PID = 0x0f32
KIT_VERSION = "2.0.0"

class MchpAwsZTKitDevice():
    def __init__(self, device):
        super(MchpAwsZTKitDevice, self).__init__()
        self.device = device
        self.report_size = 64
        self.next_app_cmd_id = 0
        self.app_responses = {}
        self.kit_reply_regex = re.compile('^([0-9a-zA-Z]{2})\\(([^)]*)\\)')

    def open(self, vendor_id=DEVICE_HID_VID, product_id=DEVICE_HID_PID):
        """Opens HID device for the AWS Zero-touch Kit. Adjusts default VID/PID for the kit."""
        self.app_responses = {}
        return self.device.open(vendor_id, product_id)

    def raw_write(self, data):
        """Write arbitrary number of bytes to the kit."""
        # Break up data into hid report chunks
        for i in range(0, len(data), self.report_size):
            chunk = data[i:i+self.report_size]
            # Prepend fixed report ID of 0, then pad with EOT characters
            self.device.write(b'\x00' + chunk + b'\x04'*(self.report_size - len(chunk)))

    def kit_write(self, target, data):
        """Write a kit protocol command to the device."""
        self.raw_write(bytes('%s(%s)\n' % (target, binascii.b2a_hex(data).decode('ascii')), encoding='ascii'))

    def kit_write_app(self, method, params=None):
        """Write an app-specific command to the device."""
        if params is None:
            params = {} # No params should be encoded as an empty object
        cmd = {'method':method, 'params':params, 'id':self.next_app_cmd_id}
        self.next_app_cmd_id = self.next_app_cmd_id + 1
        self.kit_write('board:app', bytes(json.dumps(cmd), encoding='ascii'))
        return self.next_app_cmd_id - 1

    def kit_read(self, timeout_ms=0):
        """Wait for a kit protocol response to be returned."""
        # Kit protocol data is all ascii
        data = []
        # Read until a newline is encountered after printable data
        while 10 not in data:
            chunk = self.device.read(self.report_size, timeout_ms=timeout_ms)
            if len(chunk) <= 0:
                raise RuntimeError('Timeout (>%d ms) waiting for reply from kit device.' % timeout_ms)
            if len(data) == 0:
                # Disregard any initial non-printable characters
                for i in range(0, len(chunk)):
                    if chunk[i] > 32:
                        break
                chunk = chunk[i:]
            data += chunk
        data = data[:data.index(10)+1] # Trim any data after the newline
        return ''.join(map(chr, data)) # Convert data from list of integers into string

    def parse_kit_reply(self, data):
        """Perform basic parsing of the kit protocol replies.
        - XX(YYZZ...)
        - where XX is the status code in hex and YYZZ is the reply data
        """
        match = self.kit_reply_regex.search(data)
        if match is None:
            raise ValueError('Unable to parse kit protocol reply: %s' % data)
        return {'status': int(match.group(1), 16), 'data': match.group(2)}

    def kit_read_app(self, id):
        """Read an application specific command response."""
        while id not in self.app_responses:
            data = self.kit_read()
            kit_resp = self.parse_kit_reply(data)
            if kit_resp['status'] != 0:
                raise RuntimeError('Kit protocol error. Received reply %s' % data)
            app_resp = json.loads(binascii.a2b_hex(kit_resp['data']).decode('ascii'))
            self.app_responses[app_resp['id']] = app_resp

        app_resp = self.app_responses[id]
        del self.app_responses[id]
        return app_resp

    def kit_read_app_no_error(self, id):
        """Read an application specific command response and throw an error if
           the response indicates a command error."""
        resp = self.kit_read_app(id)
        if resp['error'] is not None:
            raise MchpAwsZTKitError(resp['error'])
        return resp

    def init(self, kit_version=KIT_VERSION):
        """Initialize the device for the demo."""
        id = self.kit_write_app('init', {'version':kit_version})
        resp = self.kit_read_app_no_error(id)
        return resp['result']

    def gen_csr(self):
        """Request a CSR from the device."""
        id = self.kit_write_app('genCsr')
        resp = self.kit_read_app_no_error(id)
        return resp['result']

    def save_credentials(self, host_name, device_cert, signer_cert, signer_ca_public_key):
        """Save credentials and connection information to the device."""
        params = {}
        params['hostName']= host_name
        params['deviceCert'] = binascii.b2a_hex(device_cert).decode('ascii')
        params['signerCert'] = binascii.b2a_hex(signer_cert).decode('ascii')
        params['signerCaPublicKey'] = binascii.b2a_hex(signer_ca_public_key).decode('ascii')
        id = self.kit_write_app('saveCredentials', params)
        id = self.kit_read_app_no_error(id)

    def save_iot_credentials(self, iot_cert_1, iot_cert_2, iot_cert_1_public_key, iot_cert_2_public_key):
        """Save credentials and connection information to the device."""
        params = {}
        params['iotCert1'] = binascii.b2a_hex(iot_cert_1).decode('ascii')
        params['iotCert2'] = binascii.b2a_hex(iot_cert_2).decode('ascii')
        params['iotCert1PublicKey'] = binascii.b2a_hex(iot_cert_1_public_key).decode('ascii')
        params['iotCert2PublicKey'] = binascii.b2a_hex(iot_cert_2_public_key).decode('ascii')
        id = self.kit_write_app('saveIoTCredentials', params)
        id = self.kit_read_app_no_error(id)

    def set_wifi(self, ssid, psk):
        """Save the Wifi settings to the device."""
        id = self.kit_write_app('setWifi', {'ssid':ssid, 'psk':psk})
        id = self.kit_read_app_no_error(id)

    def get_thing_id(self):
        """Get Thing ID."""
        id = self.kit_write_app('getThingID')
        id = self.kit_read_app_no_error(id)
        return id['result']

    def reset_kit(self):
        """Reset the kit to factory state, deleting all information."""
        id = self.kit_write_app('resetKit')
        resp = self.kit_read_app_no_error(id)

    def get_status(self):
        """Get the current status of the kit."""
        id = self.kit_write_app('getStatus')
        resp = self.kit_read_app_no_error(id)
        return resp['result']

class MchpAwsZTKitError(Exception):
    def __init__(self, error_info):
        self.error_code = error_info['error_code']
        self.error_msg  = error_info['error_msg']
        super(MchpAwsZTKitError, self).__init__('Kit error %d: %s' % (self.error_code, self.error_msg))

def main():
    # Create argument parser to document script use
    parser = argparse.ArgumentParser(description='Provisions the kit by requesting a CSR and returning signed certificates.')
    args = parser.parse_args()

    kit_info = read_kit_info()

    print('\nOpening AWS Zero-touch Kit Device')
    device = MchpAwsZTKitDevice(hid.device())
    #device = MchpAwsZTKitDevice(SimMchpAwsZTHidDevice())
    device.open()

    print('\nInitializing Kit')
    resp = device.init()
    print('    ATECC508A SN: %s' % resp['deviceSn'])
    print('    ATECC508A Public Key:')
    int_size = int(len(resp['devicePublicKey']) / 2)
    print('        X: %s' % resp['devicePublicKey'][:int_size])
    print('        Y: %s' % resp['devicePublicKey'][int_size:])

    kit_info['device_sn'] = resp['deviceSn']
    save_kit_info(kit_info)
    
    print('\nLoading root Google IoT certificate: GTS LTSR')
    IOT_GTSLTSR_FILENAME = 'gtsltsr.pem'
    if not os.path.isfile(IOT_GTSLTSR_FILENAME):
        raise AWSZTKitError('Failed to find Google IoT certificate file, ' + IOT_GTSLTSR_FILENAME)
    with open(IOT_GTSLTSR_FILENAME, 'rb') as f:
        print('    Loading from ' + f.name)
        iot_cert_1 = x509.load_pem_x509_certificate(f.read(), crypto_be)
        
    print('\nLoading root Google IoT certificate: GSR4')
    IOT_GSR4_FILENAME = 'GSR4.pem'
    if not os.path.isfile(IOT_GSR4_FILENAME):
        raise AWSZTKitError('Failed to find Google IoT certificate file, ' + IOT_GSR4_FILENAME)
    with open(IOT_GSR4_FILENAME, 'rb') as f:
        print('    Loading from ' + f.name)
        iot_cert_2 = x509.load_pem_x509_certificate(f.read(), crypto_be)

    print('\nLoading root CA certificate')
    if not os.path.isfile(ROOT_CA_CERT_FILENAME):
        raise AWSZTKitError('Failed to find root CA certificate file, ' + ROOT_CA_CERT_FILENAME + '. Have you run ca_create_root first?')
    with open(ROOT_CA_CERT_FILENAME, 'rb') as f:
        print('    Loading from ' + f.name)
        root_ca_cert = x509.load_pem_x509_certificate(f.read(), crypto_be)

    print('\nLoading signer CA key')
    if not os.path.isfile(SIGNER_CA_KEY_FILENAME):
        raise AWSZTKitError('Failed to find signer CA key file, ' + SIGNER_CA_KEY_FILENAME + '. Have you run ca_create_signer_csr first?')
    with open(SIGNER_CA_KEY_FILENAME, 'rb') as f:
        print('    Loading from ' + f.name)
        signer_ca_priv_key = serialization.load_pem_private_key(
            data=f.read(),
            password=None,
            backend=crypto_be)

    print('\nLoading signer CA certificate')
    if not os.path.isfile(SIGNER_CA_CERT_FILENAME):
        raise AWSZTKitError('Failed to find signer CA certificate file, ' + SIGNER_CA_CERT_FILENAME + '. Have you run ca_create_signer first?')
    with open(SIGNER_CA_CERT_FILENAME, 'rb') as f:
        print('    Loading from ' + f.name)
        signer_ca_cert = x509.load_pem_x509_certificate(f.read(), crypto_be)

    if 'endpointAddress' not in kit_info:
        raise AWSZTKitError('endpointAddress not found in %s. Have you run aws_register_signer yet?' % KIT_INFO_FILENAME)

    if 'wifi_ssid' not in kit_info:
        raise AWSZTKitError('wifi_ssid not found in %s. Have you run kit_set_wifi yet?' % KIT_INFO_FILENAME)

    if 'wifi_password' not in kit_info:
        raise AWSZTKitError('wifi_password not found in %s. Have you run kit_set_wifi yet?' % KIT_INFO_FILENAME)

    print('\nRequesting device CSR')
    resp = device.gen_csr()
    device_csr = x509.load_der_x509_csr(binascii.a2b_hex(resp['csr']), crypto_be)
    if not device_csr.is_signature_valid:
        raise AWSZTKitError('Device CSR has invalid signature.')
    with open(DEVICE_CSR_FILENAME, 'wb') as f:
        print('    Saving to ' + f.name)
        f.write(device_csr.public_bytes(encoding=serialization.Encoding.PEM))

    print('\nGenerating device certificate from CSR')
    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(signer_ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.now(tz=pytz.utc).replace(minute=0,second=0)) # Device cert must have minutes and seconds set to 0
    builder = builder.not_valid_after(datetime.datetime(3000, 12, 31, 23, 59, 59)) # Should be year 9999, but this doesn't work on windows
    builder = builder.subject_name(device_csr.subject)
    builder = builder.public_key(device_csr.public_key())
    # Device certificate is generated from certificate dates and public key
    builder = builder.serial_number(device_cert_sn(16, builder))
    # Add in extensions specified by CSR
    for extension in device_csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    # Subject Key ID is used as the thing name and MQTT client ID and is required for this demo
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(builder._public_key),
        critical=False)
    issuer_ski = signer_ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
        critical=False)

    # Sign certificate 
    device_cert = builder.sign(
        private_key=signer_ca_priv_key,
        algorithm=hashes.SHA256(),
        backend=crypto_be)

    # Find the subject key ID for use as the thing name
    is_subject_key_id_found = False
    for extension in device_cert.extensions:
        if extension.oid._name != 'subjectKeyIdentifier':
            continue # Not the extension we're looking for, skip
        kit_info['thing_name'] = binascii.b2a_hex(extension.value.digest).decode('ascii')
        save_kit_info(kit_info)
        is_subject_key_id_found = True
    if not is_subject_key_id_found:
        raise RuntimeError('Could not find the subjectKeyIdentifier extension in the device certificate.')

    # Save certificate for reference
    with open(DEVICE_CERT_FILENAME, 'wb') as f:
        print('    Saving to ' + f.name)
        f.write(device_cert.public_bytes(encoding=serialization.Encoding.PEM))

    if(not True):
        #print('\nProvisioning device with AWS IoT credentials')
        pub_nums = root_ca_cert.public_key().public_numbers()
        pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
        pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)
        device.save_credentials(
            host_name=kit_info['endpointAddress'],
            device_cert=device_cert.public_bytes(encoding=serialization.Encoding.DER),
            signer_cert=signer_ca_cert.public_bytes(encoding=serialization.Encoding.DER),
            signer_ca_public_key=pubkey
        )
        print('credentials saved')
    else:
        pub_nums2 = iot_cert_1.public_key().public_numbers()
        pubkey2 =  pub_nums2.x.to_bytes(32, byteorder='big', signed=False)
        pubkey2 += pub_nums2.y.to_bytes(32, byteorder='big', signed=False)
        pub_nums3 = iot_cert_1.public_key().public_numbers()
        pubkey3 =  pub_nums3.x.to_bytes(32, byteorder='big', signed=False)
        pubkey3 += pub_nums3.y.to_bytes(32, byteorder='big', signed=False)
        device.save_iot_credentials(
            iot_cert_1=iot_cert_1.public_bytes(encoding=serialization.Encoding.DER),
            iot_cert_2=iot_cert_2.public_bytes(encoding=serialization.Encoding.DER),
            iot_cert_1_public_key=pubkey2,
            iot_cert_2_public_key=pubkey3
        )
        print('iot credentials saved')

    #print('\nUpdating WiFi settings')
    #print('    SSID:     %s' % kit_info['wifi_ssid'])
    #disp_password = 'None'
    #if kit_info['wifi_password'] is not None:
    #    disp_password = '*'*len(kit_info['wifi_password'])
    #print('    Password: %s' % disp_password)
    #device.set_wifi(ssid=kit_info['wifi_ssid'], psk=kit_info['wifi_password'])

    print('\nDone')

try:
    main()
except AWSZTKitError as e:
    print(e)