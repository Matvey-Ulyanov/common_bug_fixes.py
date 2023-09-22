# coding=utf-8
import ntplib
from datetime import datetime
import os

def set_system_time(new_time):
    os.system("sudo date -s '{}'".format(new_time.strftime('%Y-%m-%d %H:%M:%S')))

def main():
    ntp_server = 'pool.ntp.org'  # You can change this to a different NTP server if needed

    try:
        client = ntplib.NTPClient()
        response = client.request(ntp_server, version=3)
        network_time = datetime.fromtimestamp(response.tx_time)
        print "Network time:", network_time
        
        set_system_time(network_time)
        print "System time adjusted."
    except Exception as e:
        print "An error occurred:", e

if __name__ == "__main__":
    main()
