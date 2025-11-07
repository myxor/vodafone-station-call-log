import binascii
import hashlib
import json
import re
import requests
from Crypto.Cipher import AES
import paho.mqtt.client as mqtt
import yaml
from pathlib import Path
import time
import signal
import random
import urllib
import datetime

def load_config():
    try:
        config_path = Path('config.yml')
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        
        return {
            'ROUTER_IP':        config['router']['ip'],
            'ROUTER_PASSWORD':  config['router']['password'],

            'MQTT_BROKER':      config['mqtt']['broker'],
            'MQTT_PORT':        config['mqtt']['port'],
            'MQTT_USERNAME':    config['mqtt']['username'],
            'MQTT_PASSWORD':    config['mqtt']['password'],

            'MQTT_TOPIC_PHONE_STATE':   config['mqtt']['topic_phone_state'],
        }
    
    except FileNotFoundError:
        raise FileNotFoundError("config.yml file not found")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing config.yml: {str(e)}")
    except KeyError as e:
        raise KeyError(f"Missing required configuration key: {str(e)}")

class Router:
    def __init__(self, address, key, timeout=10):
        self.ip_address = address
        self.url = f"http://{address}"
        self.username = "admin"
        self.password = key
        self.timeout = timeout
        self.session = requests.Session()

    def login(self):
        try:
            # Actual login
            r = self.session.get(self.url, timeout=self.timeout)
            r.raise_for_status()
            current_session_id = re.search(r"var currentSessionId = '(.+)';", r.text)[1]
            iv = re.search(r"var myIv = '(.+)';", r.text)[1]
            salt = re.search(r"var mySalt = '(.+)';", r.text)[1]

            key = hashlib.pbkdf2_hmac(
                "sha256", self.password.encode(), binascii.unhexlify(salt), 1000, 16
            )
            secret = {"Password": self.password, "Nonce": current_session_id}
            plaintext = json.dumps(secret).encode()
            cipher = AES.new(key, AES.MODE_CCM, binascii.unhexlify(iv))
            cipher.update("loginPassword".encode())
            encrypted_data = cipher.encrypt(plaintext) + cipher.digest()

            login_data = {
                "EncryptData": binascii.hexlify(encrypted_data).decode(),
                "Name": self.username,
                "AuthData": "loginPassword",
            }

            r = self.session.post(
                f"{self.url}/php/ajaxSet_Password.php",
                headers={"Content-Type": "application/json"},
                data=json.dumps(login_data),
                timeout=self.timeout,
            )
            r.raise_for_status()

            if "AdminMatch" not in r.text:
                raise Exception("Login failed")

            result = json.loads(r.text)
            csrf_nonce = AES.new(key, AES.MODE_CCM, binascii.unhexlify(iv)).decrypt(
                binascii.unhexlify(result["encryptData"])
            )[:32]
            self.session.headers.update(
                {
                    "X-Requested-With": "XMLHttpRequest",
                    "csrfNonce": csrf_nonce.decode(),
                    "Origin": f"{self.url}/",
                }
            )

        except Exception as e:
            print(f"Login error: {e}")
            return False
        return True

    def generate_ar_nonce(self):
        # 1. Generate a random float, convert to string, and get substring from index 2 for 5 characters.
        #    e.g., '0.123456789...' -> '12345'
        random_digits = str(random.random())[2:7]

        # 2. Format it exactly as follows: "_n=XXXXX"
        return f"_n={random_digits}"


    # example entry:
    # {"PhoneLogRecord":[{"ParameterIndex":1,"CallType":"Missed","Date":"PAGE_CALL_LOG_TABLE_TODAY","Time":"7:33","ExternalNumber":"0175xxxxxxxx","Duration":""}]}

    def get_phone_call_log(self):
        try:
            # Ensure self.ar_nonce and self.csrf_nonce_value are set
            nonce_digits = self.ar_nonce.split('=')[-1]

            url_path = "/php/phone_call_log_data.php"


            # The server expects the literal string: &{%22PhoneLogRecord%22:{}}
            # The string that NEEDS to be encoded is: {"PhoneLogRecord":{}}
            json_param_to_encode = '{"PhoneLogRecord":{}}'

            # We need to manually build the entire parameter *before* the first ampersand
            # The expected string is: & + encoded_json_param
            encoded_json_param = urllib.parse.quote(json_param_to_encode)

            # The full URL structure is: base_url?_n={nonce}&{encoded_json_param}
            full_url = (
                f"{self.url}{url_path}?"
                f"_n={nonce_digits}"
                # We must add the ampersand AND the outer braces, which were URL-encoded
                # in the browser's request: &{%22PhoneLogRecord%22:{}}
                # We achieve this by encoding the braces around the raw JSON string
                f"&{urllib.parse.quote('{')}{encoded_json_param}{urllib.parse.quote('}')}"
            )
            # The simplest way to replicate the CURL URL is to encode the ENTIRE complex part:
            complex_param = f'{{"PhoneLogRecord":{{}}}}'
            encoded_complex_param = urllib.parse.quote(complex_param)
            full_url = f"{self.url}{url_path}?_n={nonce_digits}&{encoded_complex_param}"


            csrf_nonce_value = self.session.headers.get('csrfNonce', '')

            request_headers = {
                    #"Host": "192.168.100.1",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
                    "Accept": "*/*",
                    "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
                    "Accept-Encoding": "gzip, deflate",
                    "csrfNonce": csrf_nonce_value,
                    "X-Requested-With": "XMLHttpRequest",
                    "DNT": "1",
                    "Sec-GPC": "1",
                    "Connection": "keep-alive",
                    "Referer": f"{self.url}/?phone_call_log",
                    "Content-Type": "application/json",
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache"
            }

            r = self.session.get(
                full_url,
                headers=request_headers,
                timeout=self.timeout
            )
            r.raise_for_status()
            if (r):
                raw_json = r.text

                data = json.loads(raw_json)

                if (data):

                    # Extract the array of call records
                    call_records = data.get("PhoneLogRecord", [])
                    return call_records

            else:
                print(f"Error getting phone_call_log")
                return []

        except Exception as e:
            print(f"Error while getting phone_call_log: {e}")


            if r and r.status_code == 400:
                print("400 error while getting phone_call_log")
                print("Either someone is logged in or old session is still active.")

            return []


    def logout(self):
        try:
            self.session.post(f"{self.url}/php/logout.php", timeout=self.timeout)
        except Exception as e:
            print(f"Logout error: {e}")

def clean_call_records(call_records):
    today_date = datetime.date.today()
    today_date_str = today_date.strftime("%Y/%m/%d")

    yesterday_date = today_date - datetime.timedelta(days=1)
    yesterday_date_str = yesterday_date.strftime("%Y/%m/%d")

    cleaned_records = []

    for record in call_records:
        # Create a mutable copy of the record
        cleaned_record = record.copy()

        # Check for the specific placeholder string
        if cleaned_record.get('Date') == 'PAGE_CALL_LOG_TABLE_TODAY':
            cleaned_record['Date'] = today_date_str
        elif cleaned_record.get('Date') == 'PAGE_CALL_LOG_TABLE_YESTERDAY':
            cleaned_record['Date'] = yesterday_date_str

        if cleaned_record.get('Duration') == "":
            cleaned_record['Duration'] = 0

        cleaned_records.append(cleaned_record)

    return cleaned_records


def publish_discovery_config(client):
    """Publishes the configuration payload for Home Assistant MQTT Discovery."""

    # The discovery topic (uses the 'homeassistant' prefix)
    discovery_topic = "homeassistant/sensor/router_call_log_summary/config"

    # The topic where the sensor's actual state and attributes will be published
    state_topic = f"vodafone_station/call_log_summary/state"

    config_payload = {
        "name": "Router Call Log Summary",
        "unique_id": "router_log_summary_total",
        "state_topic": state_topic,
        "value_template": "{{ value_json.state }}",
        "json_attributes_topic": state_topic,
        "json_attributes_template": "{{ value_json | tojson }}", # Use the full payload for attributes
        "unit_of_measurement": "calls",
        "icon": "mdi:phone-missed-outline",
        "device": {
            "identifiers": ["router_device_id"],
            "name": "Vodafone Station",
            "model": "TG3442DE",
            "manufacturer": "Arris"
        }
    }

    # Publish the configuration payload with RETAIN set to True
    # Retaining the message ensures Home Assistant rediscovers the sensor after a restart.
    client.publish(discovery_topic, json.dumps(config_payload), retain=True)

    print(f"Published discovery config to: {discovery_topic}")

def publish_call_log_summary(client, call_records):
    # State: Total number of records (e.g., total calls)
    state_value = len(call_records)

    # Payload for MQTT (The state is the count, attributes hold the detail)
    payload = {
        "state": state_value,
        "records": call_records
    }

    # Publish the JSON payload
    topic = f"vodafone_station/call_log_summary/state"
    client.publish(topic, json.dumps(payload), retain=True)

    print(f"Published state of {state_value} call logs to: {topic}")

def logout():
    router.logout()
    client.disconnect()
    print("Logged out")


# Register the signal handler
signal.signal(signal.SIGTERM, logout)

if __name__ == "__main__":
    config = load_config()
    router = Router(config['ROUTER_IP'], config['ROUTER_PASSWORD'])
    old_devices = []

    try:
        client = mqtt.Client()
        client.username_pw_set(config['MQTT_USERNAME'], config['MQTT_PASSWORD'])
        client.connect(config['MQTT_BROKER'], config['MQTT_PORT'], 60)
            
        if router.login():

            print("Logged in")

            router.ar_nonce = router.generate_ar_nonce()
            call_records = router.get_phone_call_log()
            if (call_records):
                call_records = clean_call_records(call_records)

                publish_discovery_config(client)
                publish_call_log_summary(client, call_records)
            else:
                print("No call records found")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        logout()
