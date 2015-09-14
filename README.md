# Portwatcher
This Python script is designed to conduct daily TCP portscans using Nmap and email the open and closed changes to a client. Note: The script ignores filtered ports. Additionally the script will scan all ip's supplied on all ports regardless of ping status.

Scans are setup using the .conf and .hosts files, (see examples).
Typically the script is placed in /opt/watcher and started via crontab entries. 
Output is placed in /var/log/watcher.

crontab example:
00 01 * * * /usr/bin/python /opt/watcher/watcher.py /opt/watcher/test.conf >> /var/log/watcher/cron.log 2>&1

# Dependencies

  - metplotlib for graphing (sudo apt-get install python-matplotlib )
  - nmap for scanning (sudo apt-get install nmap)
  - mutt for email (sudo apt-get insatll mutt)

Note: SMTP email must be setup and working on the box (ie. sendmail working)
