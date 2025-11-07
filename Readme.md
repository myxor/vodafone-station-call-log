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

5. Integration to Home Assistant is done by the script

## Home-Assistant sensors

The script will create a sensor called `sensor.vodafone_station_router_call_log_summary` showing the number of calls in the log as value:

    records:
    - CallType: Dialed
        Date: "2025-11-06"
        Duration: 0
        ExternalNumber: "017xxxxxxx"
        ParameterIndex: 2
        Time: "10:14"
    - CallType: Missed
        Date: "2025-11-06"
        Duration: 0
        ExternalNumber: "017xxxxxxx"
        ParameterIndex: 1
        Time: "7:33"
    unit_of_measurement: calls
    icon: mdi:phone-missed-outline
    friendly_name: Vodafone Station Router Call Log Summary

### Sensor to show type of last call type

    {% set records = state_attr('sensor.vodafone_station_router_call_log_summary', 'records') %}
    {% if records %}
    {{ records[0].CallType }}
    {% else %}
    -
    {% endif %}
  
### Sensor to show type of last calls external number
    
    {% set records = state_attr('sensor.vodafone_station_router_call_log_summary', 'records') %}
    {% if records %}
    {{ records[0].ExternalNumber }}
    {% else %}
    None
    {% endif %}

## Thanks

Based on https://github.com/vggscqq/vodafone-mqtt

Special thanks to vggscqq!

## Contribution
If your router is supported or you add support for a different firmware or hardware version, feel free to contribute back to this project.

## License
This project is licensed under the GPL License.
