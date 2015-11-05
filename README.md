# Portwatcher
This Python script is designed to conduct daily TCP & UDP portscans using Nmap. The differences between yesterdays scan and todays are then emailed to a client, if there is no change no email is sent. Additionally there is some graphing and a responding IP list.

Note: Change the Nmap command in the script as required.. by default the script ignores filtered ports & uses the default Nmap 1000 port scan, ignoring ping status with no reverse DNS. Additional config data such as max and min rates and UDP on/off are present in the .conf files.

Scans are setup using the .conf and .hosts files, (see examples).
Typically the script is placed in /opt/watcher and started via root crontab entries (Nmap needs root :(). 
Output is placed in /var/log/watcher.

crontab example:
00 01 * * * /usr/bin/python /opt/watcher/watcher.py /opt/watcher/test.conf >> /var/log/watcher/cron.log 2>&1

# Dependencies

  - metplotlib for graphing (sudo apt-get install python-matplotlib)
  - nmap for scanning (sudo apt-get install nmap)
  - mutt for email (sudo apt-get insatll mutt)

Note: SMTP email must be setup and working on the box (ie. sendmail working)

# Disclaimer

This program is free to use/modify/stick-up-your-arse™. No warranty or any expectation that this actually works (it does work*) is provided, use at own skill. 
