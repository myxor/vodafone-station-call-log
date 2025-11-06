# vodafone-station-call-log

**MQTT exporter for Vodafone Station / Arris TG3442DE routers**

## Overview
This project provides an MQTT exporter to monitor phone call log. 

It has been tested on the following router configuration:

- **Firmware Version:** `01.04.137.07.EURO.SIP`
- **Hardware Version:** `9`

The exporter can be integrated with Home Assistant or other MQTT-compatible platforms to provide monitoring and automation.



## Installation and Usage
1. Clone the repository:

```bash
git clone https://github.com/myxor/vodafone-station-call-log.git
cd vodafone-station-call-log
```

2. Install the dependencies:
```bash
pip install -r requirements.txt
```

3. Create a config.yml file in the root directory with your router and MQTT configuration:
[config.yml](https://github.com/myxor/vodafone-station-call-log/blob/main/config.yml_example)

4. Run the script:
```bash
python vodafone_mqtt.py
```

5. Integrate to Home Assistant.

## Thanks

Based on https://github.com/vggscqq/vodafone-mqtt

Special thanks to vggscqq!

## Contribution
If your router is supported or you add support for a different firmware or hardware version, feel free to contribute back to this project.

## License
This project is licensed under the GPL License.
