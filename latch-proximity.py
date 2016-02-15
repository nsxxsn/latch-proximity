#!/usr/bin/python

import subprocess
import time
import os
import signal
import re
import hashlib, uuid
import pickle
import latch

class scanBTLEDevices():

    def __init__(self, *args, **kwargs):

        self.HCI_LESCAN_COMMAND = "hcitool lescan" # bluez command-line 
        self.HCI_RESTART_COMMAND = "hciconfig hci0 reset"
        self.LATCH_APP_ID = ''
        self.LATCH_APP_SECRET = ''

        self.TIMER_SCAN = 2 # time in seconds to scan devices
        self.MAX_RETRY_HCI = 3

        self.retry_hci_counter = 0
        self.list_tokens = []

        self.salt_hex = self.load_salt()
        self.hashed_mac = self.load_hashed_mac()

        self.api_latch = latch.Latch(self.LATCH_APP_ID, self.LATCH_APP_SECRET)
        self.latch_token = self.load_latch_token()

        if self.latch_token == None:
            self.latch_token = self.pair_latch_token() # ask for a latch pairing token

        if self.hashed_mac == None:
            self.hashed_mac = self.input_token_mac() # ask for a user MAC Address

    def input_token_mac(self):

        input_mac = raw_input('Please, introduce your token MAC Address:')
        try:
            input_mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', str(input_mac.upper()), re.I).group()
        except:
            self.input_token_mac()
        # check that it is a valid MAC address
        if len(input_mac) != 17: 
            self.input_token_mac()
    
        return self.save_hashed_mac(input_mac)


    def generate_salt(self):

        # generate a valid UUID salt file and save it
        salt_hex = uuid.uuid4().hex
        with open('salt.file', 'wb') as f:
            pickle.dump(salt_hex, f)
        return salt_hex

    def load_salt(self):

        # load a salt file already generated or create a new one
        try:
            with open('salt.file', 'rb') as f:
                return pickle.load(f)
        except IOError as e:
            print 'Not salt file found. Creating!'
            return (self.generate_salt())
        except EOFError as e:
            print 'Incorrect salt file. Re-creating!'
            return (self.generate_salt())

    def hash_mac(self, mac_address):

        # Using a high encryption hashing function, generate MAC Address
        return hashlib.sha512(mac_address + self.salt_hex).hexdigest()

    def save_hashed_mac(self, mac_address):

        hashed_mac = self.hash_mac(mac_address)
        with open('mac.file', 'wb') as f:
            pickle.dump(hashed_mac, f)
        return hashed_mac

    def load_hashed_mac(self):

        try:
            with open('mac.file', 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print 'Exception found while opening MAC Address', str(e)
            return None

    def save_latch_token(self, token):

        with open('latch.file', 'wb') as f:
            pickle.dump(str(token), f)
        return str(token)

    def load_latch_token(self):

        try:
            with open('latch.file', 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print 'Latch token not found.', str(e)
            return None

    def pair_latch_token(self):

        token = None
        pairing_id = raw_input('Please, introduce your Latch pairing token:')
        print 'Pairing ...'
        response = self.api_latch.pair(pairing_id)

        if response.get_data()['accountId'] != None:
            token = response.get_data()['accountId']
        else:
            print 'Error while pairing: ', response.get_error()
            self.pair_latch_token()

        return self.save_latch_token(token)

    def scan_btle(self, process_data):

        process = subprocess.Popen(self.HCI_LESCAN_COMMAND.split(), stdout = subprocess.PIPE)
        time.sleep(self.TIMER_SCAN)
        os.kill(process.pid, signal.SIGINT)
        output = process.communicate()[0]

        if process_data == True:
            token_detected = self.process_hci(output)
            if token_detected != None:

                response = None
                try:
                    status = self.api_latch.status(self.latch_token, silent = True).to_json()
                    status = status['data']['operations'][self.LATCH_APP_ID]['status']
                except Exception as e:
                    status == 'on' # in case there is a problem ensure we lock the latch
                    print 'status excepted', str(e)

                if token_detected == False and status.lower() == 'on':
                    print 'Token not found and latch is deactivated! - Latching'
                    response = self.api_latch.lock(self.latch_token)

                if response != None:
                    if len(response.get_error()) > 0:
                        print 'Error locking/unlocking app', response.get_error()

    def process_hci (self, output):

        if output == '':
            # "Set scan parameters failed: Operation not permitted" message found
            print 'Error launching program. Make sure you have sudo permissions.'
            self.restart_adapter()
            self.scan_btle(True)
            return None

        if output == None:
            return None

        # Remove the first (info line) and the last element (empty line)
        devices = output.split('\n')[1:-1]
        self.list_tokens = []

        for device in devices:
            mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', str(device), re.I).group()
            self.list_tokens.append(self.hash_mac(mac))

        return self.check_user_proximity()

    def check_user_proximity(self):

        # check if the user token is included in the hashed scanned macs list
        return self.hashed_mac in self.list_tokens

    def restart_adapter(self):

        self.retry_hci_counter += 1
        subprocess.Popen(self.HCI_RESTART_COMMAND.split(), stdout = subprocess.PIPE)
        time.sleep(self.TIMER_SCAN)
        if self.retry_hci_counter == self.MAX_RETRY_HCI:
            print 'Maximum adapter restarts done. Exiting program.'
            exit(0)

if __name__ == '__main__':

    scanner = scanBTLEDevices()
    while True:
        scanner.scan_btle(True)
