
#!/usr/bin/python
# Author: Remy van Elst (https://raymii.org)
# License: GNU GPLv2
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import urllib.request as urllib
import ssl
import sys
import string
import re
from prettytable import PrettyTable
from datetime import datetime

auth_token = "YOURTOKENHERE"
api_url = "YOURAPI"

request_headers = {
	"Accept-Language": "en-US,en;q=0.5",
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"X-Auth-Token": auth_token,
	"Connection": "keep-alive"
}

# https://gist.github.com/benhagen/5296795
def is_ipv4(ip):
	match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
	if not match:
		return False
	quad = []
	for number in match.groups():
		quad.append(int(number))
	if quad[0] < 1:
		return False
	for number in quad:
		if number > 255 or number < 0:
			return False
	return True

class LibreNMSAPI(object):
	"""Mapping for certain LibreNMS API endpoints
	https://github.com/librenms/librenms/tree/master/doc/API
	"""
	def __init__(self, auth_token=auth_token, request_headers=request_headers, api_url=api_url):
		super(LibreNMSAPI, self).__init__()
		self.api_url = api_url
		self.request_headers = request_headers
		self.auth_token = auth_token

	def get_alert_rule(self,rule_id):
		rule_req = urllib.Request(self.api_url + "rules/" + str(rule_id), headers=self.request_headers)
		rule_contents = urllib.urlopen(rule_req).read()
		return json.loads(str(rule_contents.decode('utf-8')))["rules"][0]

	def get_alert(self, alert_id):
		alert_req = urllib.Request(self.api_url + "alert/" + alert_id, headers=self.request_headers)
		alert_contents = urllib.urlopen(alert_req).read()
		return json.loads(alert_contents)

	def get_alerts(self, state="ALL"):
		if state == "ALL":
			alerts_req = urllib.Request(self.api_url + "alerts", headers=self.request_headers)
		else:
			alerts_req = urllib.Request(self.api_url + "alerts?state=" + state, headers=self.request_headers)
		alerts_contents = urllib.urlopen(alerts_req).read()
		return json.loads(str(alerts_contents.decode('utf-8')))

	def get_device(self, device_id):
		device_req = urllib.Request(self.api_url + "devices/" + str(device_id), headers=self.request_headers)
		device_contents = urllib.urlopen(device_req).read()
		return json.loads(str(device_contents.decode('utf-8')))["devices"][0]

	def get_devices(self):
		devices_req = urllib.Request(self.api_url + "devices", headers=self.request_headers)
		devices_contents = urllib.urlopen(devices_req).read()
		return json.loads(str(devices_contents.decode('utf-8')))["devices"]


	def translate_device_ip_to_sysname(self, device):
		"""If hostname is an IPv4, return the sysname, 
		that might be more descriptive"""
		hostname = device["hostname"]
		if is_ipv4(hostname):
			return device["sysName"]
		return device["hostname"]



librenms_api = LibreNMSAPI(auth_token=auth_token, request_headers=request_headers, api_url=api_url)
alerts = librenms_api.get_alerts()
devices = librenms_api.get_devices()

#icmp_up_devices = PrettyTable()
#icmp_up_devices.field_names = ["Hostname", "Notes", "Up since", "Location"]
#icmp_down_devices = PrettyTable()
#icmp_down_devices.field_names = ["Hostname", "Notes", "Down since", "Location"]
#ok_alerts = PrettyTable()
#ok_alerts.field_names = ["Hostname", "Alert rule", "OS Version", "Location"]
#critical_alerts = PrettyTable()
#critical_alerts.field_names = ["Hostname", "Alert rule", "OS Version", "Location"]
#warning_alerts = PrettyTable()
#warning_alerts.field_names = ["Hostname", "Alert rule", "OS Version", "Location"]

uptime = 0
downtime = 0

##UP
for device in devices :
	if device["status_reason"] != "icmp":
		if device["status"] == 1:
			device_up_since = device ["last_ping"]
			device_location = re.sub(r'\[.*\]', '', device["location"]) # remove gps coords
			device_hostname = librenms_api.translate_device_ip_to_sysname(device)
			device_purpose = device["purpose"]
                        #icmp_up_devices.add_row([device_hostname, device_purpose, device_up_since, device_location])
			print('DEVICES UP')
			print('---------------------------'.replace("\\r\\n", " "))
			print('Hostname : '+ device_hostname.replace("\\r\\n", " "))
			print('Notes : '+ str(device_purpose).replace("\\r\\n", " "))
			print('TimeStamp : '+ device_up_since.replace("\\r\\n", " "))
			print('Location : '+ device_location.replace("\\r\\n", " "))
			print('---------------------------'.replace("\\r\\n", " "))
			uptime+=1


##DOWN
for device in devices:
	if  device["status_reason"] == "icmp":
		if  device["ignore"] == 0 or device["disabled"] == 0:
			device_down_since = device["last_ping"]
			device_location = re.sub(r'\[.*\]', '', device["location"]) # remove gps coords
			device_hostname = librenms_api.translate_device_ip_to_sysname(device)
			device_purpose = device["purpose"]
			#icmp_down_devices.add_row([device_hostname, device_purpose, device_down_since, device_location])
			print('DEVICES DOWN'.replace("\\r\\n", " "))
			print('---------------------------'.replace("\\r\\n", " "))
			print('Hostname : '+device_hostname.replace("\\r\\n", " "))
			print('Notes : '+str(device_purpose).replace("\\r\\n", " "))
			print('TimeStamp : '+device_down_since.replace("\\r\\n", " "))
			print('Location : '+device_location.replace("\\r\\n", " "))
			print('---------------------------'.replace("\\r\\n", " "))
			downtime+=1

alert_ok = 0
alert_warning = 0
alert_critical = 0

## OK ALERTS
for alert in alerts["alerts"]:
	alert_rule = librenms_api.get_alert_rule(alert["rule_id"])
	device = librenms_api.get_device(alert["device_id"])
	device_status = device["status"]
	device_status_reason = device["status_reason"]
	device_hostname = librenms_api.translate_device_ip_to_sysname(device)
	device_location = re.sub(r'\[.*\]', '', device["location"]) # remove gps coords
	alert_severity = alert["severity"]

	##Device that are showing ok
	#if device_status_reason == "icmp":
	#	if alert_severity == "ok":
        #                ok_alerts.add_row([device_hostname, alert_rule["name"], device["version"], device_down_since, device_location])


	## devices that are down due to ping (not snmp timeout, snmp is flaky for down detection)
	#if not device_status_reason == "icmp":
	if alert_severity == "ok":
		#ok_alerts.add_row([device_hostname, alert_rule["name"], device["version"], device_location])
		print('OK ALERTS'.replace("\\r\\n", " "))
		print('---------------------------'.replace("\\r\\n", " "))
		print('Hostname : '+device_hostname.replace("\\r\\n", " "))
		print('Alert Rule : '+alert_rule["name"].replace("\\r\\n", " "))
		print('OS Version : '+device["version"].replace("\\r\\n", " "))
		print('Location : '+device_location.replace("\\r\\n", " "))
		print('---------------------------'.replace("\\r\\n", " "))
		alert_ok+=1

##WARNING ALERTS
for alert in alerts["alerts"]:
	alert_rule = librenms_api.get_alert_rule(alert["rule_id"])
	device = librenms_api.get_device(alert["device_id"])
	device_status = device["status"]
	device_status_reason = device["status_reason"]
	device_hostname = librenms_api.translate_device_ip_to_sysname(device)
	device_location = re.sub(r'\[.*\]', '', device["location"]) # remove gps coords
	alert_severity = alert["severity"]

	if alert_severity == "warning":
		#warning_alerts.add_row([device_hostname, alert_rule["name"], device["version"], device_location])
		print('WARNING ALERTS'.replace("\\r\\n", " "))
		print('---------------------------'.replace("\\r\\n", " "))
		print('Hostname : '+device_hostname.replace("\\r\\n", " "))
		print('Alert Rule : '+ alert_rule["name"].replace("\\r\\n", " "))
		print('OS Version : '+device["version"].replace("\\r\\n", " "))
		print('Location : '+device_location.replace("\\r\\n", " "))
		print('---------------------------'.replace("\\r\\n", " "))
		alert_warning+=1

##CRITICAL ALERTS
for alert in alerts["alerts"]:
	alert_rule = librenms_api.get_alert_rule(alert["rule_id"])
	device = librenms_api.get_device(alert["device_id"])
	device_status = device["status"]
	device_status_reason = device["status_reason"]
	device_hostname = librenms_api.translate_device_ip_to_sysname(device)
	device_location = re.sub(r'\[.*\]', '', device["location"]) # remove gps coords
	alert_severity = alert["severity"]


	if alert_severity == "critical":
		#critical_alerts.add_row([device_hostname, alert_rule["name"], device["version"], device_location])
		print('CRITICAL ALERTS'.replace("\\r\\n", " "))
		print('---------------------------'.replace("\\r\\n", " "))
		print('Hostname : '+device_hostname.replace("\\r\\n", " "))
		print('Alert Rule : '+alert_rule["name"].replace("\\r\\n", " "))
		print('OS Version : '+device["version"].replace("\\r\\n", " "))
		print('Location : '+device_location.replace("\\r\\n", " "))
		print('---------------------------'.replace("\\r\\n", " "))
		alert_critical+=1


#print("Devices Up: ({0}) ".format(icmp_up_devices.rowcount))
#if icmp_up_devices.rowcount > 0:
#	print(icmp_up_devices.get_string(attributes={"border":"1"}))
print('Devices Up: '+str(uptime).replace("\\r\\n", " "))


#print("Devices Down: ({0}) ".format(icmp_down_devices.rowcount))
#if icmp_down_devices.rowcount > 0:
	#print(icmp_down_devices.get_string(attributes={"border":"1"}))
print('Devices Down: '+str(downtime).replace("\\r\\n", " "))

#print("OK Alerts: ({0}) ".format(ok_alerts.rowcount))
#if ok_alerts.rowcount > 0:
        #print(ok_alerts.get_string(attributes={"border":"1"}))
print('OK Alerts: '+str(alert_ok).replace("\\r\\n", " "))

#print("Warning alerts: ({0}) ".format(warning_alerts.rowcount))
#if warning_alerts.rowcount > 0:
        #print(warning_alerts.get_string(attributes={"border":"1"}))
print('Warning Alerts: '+str(alert_warning).replace("\\r\\n", " "))

#print("Critical alerts: ({0}) ".format(critical_alerts.rowcount))
#if critical_alerts.rowcount > 0:
	#print(critical_alerts.get_string(attributes={"border":"1"}))
print('Critical Alerts: '+str(alert_critical).replace("\\r\\n", " "))



