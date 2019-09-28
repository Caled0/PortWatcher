# Portwatcher
This Python script is designed to conduct daily TCP & UDP portscans using Nmap. The differences between yesterdays scan and todays are then emailed to a client, if there is no change no email is sent. Additionally there is some graphing and a responding IP list.

Note: Change the Nmap command in the script as required.. by default the script ignores filtered ports & uses the default Nmap 1000 port scan, ignoring ping status with no reverse DNS. Additional config data such as max and min rates and UDP on/off are present in the .conf file, if you find scans are going to slow, refer to these settings.

Scans are setup using the .conf and .hosts files, (see examples).
Typically the script is placed in /opt/watcher and started via root crontab entries (Nmap needs root :(). 
Output is placed in /var/log/watcher.

crontab example:
00 01 * * * /usr/bin/python /opt/watcher/watcher.py /opt/watcher/test.conf >> /var/log/watcher/cron.log 2>&1

# Dependencies

  - metplotlib for graphing (sudo apt-get install python-matplotlib)
  - nmap for scanning (sudo apt-get install nmap)
  - mutt for email (sudo apt-get insatll mutt)

NOTE: SMTP email must be setup and working on the box before you install mutt (ie. sendmail working), todo this:

Under Ubuntu:
sudo apt-get install ssmtp
sudo nano /etc/ssmtp/ssmtp.conf

Gmail config example:
root=YOURUSERNAME@gmail.com
mailhub=smtp.gmail.com:587
AuthUser=YOURUSERNAME
AuthPass=YOURPASSWORD
UseSTARTTLS=YES
UseTLS=YES
mailhub=smtp.gmail.com:587

NOTE: For gmail you will need to enable "less secure apps" under https://myaccount.google.com/lesssecureapps

# Disclaimer

Please refer to LICENSE file.
