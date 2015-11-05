from datetime import date
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys
import os
import re

# Port Watcher 1.4 - https://github.com/Caled0/PortWatcher
# Requires Metplotlib library for graphing, nmap for scanning & mutt for mail
# sudo apt-get install python-matplotlib
# sudo apt-get install nmap		
# sudo apt-get insatll mutt
# example: python watcher.py /opt/watcher/test.conf


def statics():					# Function to hold global static variables
	statics.scanname = ""
	statics.hostsfile = ""
	statics.minrate = ""
	statics.maxrate = ""
	statics.recipients = ""
	statics.retries = ""
	statics.day = date.today()
	statics.filename = ""
	statics.newgraphlist = []
	statics.newdiffout = []
	statics.newlivehosts = 0
	statics.oldlivehosts = 0
	statics.oldgraphlist = []
	statics.olddiffout = []
	statics.prevfile = ""
	statics.prev = 0
	statics.change = 0
	statics.diffout = []
	statics.numclosed = 0
	statics.numopen = 0
	statics.graphopen = []
	statics.graphclosed = []
	statics.graphlivenew = []
	statics.graphliveold = [] 
	statics.difffilename = ""
	statics.udp = ""
	return

def config():										# Function to process config file input
	print "Processing config file..................."
	
	ebuf = []
	checks = ["RECIPIENTS", "SCANNAME", "HOSTSFILE", "MINRATE", "MAXRATE", "RETRIES", "UDP"]
	for object in checks:
		cname = str(sys.argv[1])
		cfile = open(cname)
		for line in cfile:
			if str(object) in line:
				c = list(line)
				x = 0
				y = len(c)
				st = ""
				ch = 0
				while x < y:
					if ch == 1:
						if c[x] is ",":
							ch = 0
							if str(object) is "RECIPIENTS":
								ebuf.append(st)
							st = ""
						if c[x] is '"':
							ch = 0
							if str(object) is "RECIPIENTS":
								ebuf.append(st)
							if str(object) is "SCANNAME":
								statics.scanname = st
							if str(object) is "HOSTSFILE":
								statics.hostsfile = st
							if str(object) is "MINRATE":
								statics.minrate = st
							if str(object) is "MAXRATE":
								statics.maxrate = st
							if str(object) is "RETRIES":
								statics.retries = st
							if str(object) is "UDP":
								statics.udp = st
							st = ""
						if ch != 0:
							if c[x] is " ":
								pass
							else:
								st = st + c[x]
					if ch == 0:
						if c[x] is '"':
							ch = 1
						if c[x] is ',':
							ch = 1
					x = x + 1
		cfile.close()	
	est = str(ebuf)
	est = est.strip("[")
	est = est.strip("]")
	est = est.replace("'", "")
	statics.recipients = est
	if statics.recipients is "":
		print "ERROR - Invalid recipients data in config file"
		sys.exit()
	if statics.hostsfile is "":
		print "ERROR - Invalid hostsfile data in config file"
		sys.exit()
	if statics.scanname is "":
		print "ERROR - Invalid scanname data in config file"
		sys.exit()
	if statics.minrate is "":
		print "ERROR - Invalid minrate data in config file"
		sys.exit()
	if statics.maxrate is "":
		print "ERROR - Invalid maxrate data in config file"
		sys.exit()
	if statics.retries is "":
		print "ERROR - Invalid retries data in config file"
		sys.exit()
	if statics.udp == "":
		print "ERROR - Invalid UDP data in config file"
		sys.exit()
	if os.path.exists(statics.hostsfile):
		pass
	else:
		print "ERROR - .conf file does not exist!"
	if os.path.isdir("/var/log/watcher/" + statics.scanname):
		pass
	else:
		os.system("mkdir /var/log/watcher/" + statics.scanname)	
	return
	
def scan():																# Function to conduct nmap scans
	print str(statics.day) + " - " + str(statics.scanname)
	print "Conducting scans.... "
	statics.filename = "/var/log/watcher/" + statics.scanname + "/" + statics.scanname + "-" + str(statics.day)
	statics.prevfile = "/var/log/watcher/" + statics.scanname + "/" + statics.scanname + "-" + "prev.gnmap"
	if statics.udp is "0":
		command = "nmap " + "-sS -PN -n --randomize-hosts --max-retries " + statics.retries + " --max-rate " + statics.maxrate + " --min-rate " + statics.minrate + " -iL " + statics.hostsfile + " -oA " + statics.filename + " >> /var/log/watcher/" + statics.scanname + "/cron.log"
	if statics.udp is "1":
		command = "nmap " + "-sU -sS -PN -n --randomize-hosts --max-retries " + statics.retries + " --max-rate " + statics.maxrate + " --min-rate " + statics.minrate + " -iL " + statics.hostsfile + " -oA " + statics.filename + " >> /var/log/watcher/" + statics.scanname + "/cron.log"
	os.chdir("/var/log/watcher/" + statics.scanname + "/")
	os.system(command)
	statics.filename = statics.filename + ".gnmap"
	return

def process(filename, status):											# Function to process nmap output

	print "Processing scans...." + status
	
	if status is "old":
		if os.path.exists(statics.prevfile):
			pass
		else:
			print "prev.gnmap file does not exist, first scan run ?? - skipping..."
			statics.prev = 1
			return	
	
	file = open(filename, 'r')
	addr = []

	for line in file:
		if 'Ports:' in line:
			x = len(line)
			y = 0
			c = list(line)
			f = 0
			r = 0
			ip = ""
			while y < x:
				if r == 0:
					if f == 1:
						if c[y] is ' ':
							if c[y+1] is '(':
								r = 1
						if r != 1:
							ip = ip + str(c[y])
					if f == 0:
						if c[y] is 't':
							if c[y+1] is ':':
								if c[y+2] is ' ':
									f = 1
									y = y + 2
				y = y + 1
			addr.append(ip)

	addr = sorted(addr, key=lambda ip: long(''.join(["%02X" % long(i) for i in ip.split('.')]), 16))

	file.close()

	out = []
	temp = ""
	for object in addr:
		file = open(filename, 'r')
		for line in file:
			if 'Ports:' in line:
				x = len(line)
				y = 0
				c = list(line)
                		f = 0
                		ip = ""
				r = 0
				while y < x:
					if r == 0:
						if f == 1:
							if c[y] is ' ':
								if c[y+1] is '(':
									r = 1
							if r != 1:
								ip = ip + str(c[y])
						if f == 0:
							if c[y] is 't':
								if c[y+1] is ':':
									if c[y+2] is ' ':
										f = 1
										y = y + 2
					y = y + 1
				if str(ip) == str(object):
					out.append(object)
					x = len(line)
					y = 0
					c = list(line)
					f = 0
					ip = ""
					w = 0
					j = 0
					while y < x:
						if j == 0:
							if f == 1:
								if c[y] is 'I':
									if c[y+1] is 'g':
										if c[y+2] is 'n':
											if c[y+3] is 'o':
												j = 1
								if j != 1:
									ip = ip + str(c[y])
							if f == 0:
								if c[y] is 't':
									if c[y+1] is 's':
										if c[y+2] is ':':
											if c[y+3] is ' ':
												y = y + 3
												f = 1
						y = y + 1
					sp = ip.split(",")
					for thing in sp:
						g = thing.split("/")
						k = str(g[0]).strip(" ")
						h = str(g[1]).strip(" ")
						r = str(g[2]).strip(" ")
						o = str(g[4]).strip(" ")
						o = str(g[4]).replace(".","")
						out.append(k + " " + h + " " + r + " " + o)
	
	file.close()
	if status is "new":
		statics.newdiffout = out
	if status is "old":
		statics.olddiffout = out
	#print out
	return

def compare():															# Function to compare nmap scans

	print "Comparing scans...."
	
	if statics.prev == 1:
		print "prev.gnmap file does not exist, first scan run ?? - skipping..."
		string = "cp " + statics.filename + " " + statics.scanname + "-prev.gnmap"
		os.system(string)
		statics.change = 1
		return
	
	if statics.olddiffout == statics.newdiffout:
		statics.change = 1
		return
		
	a = statics.newdiffout
	b = statics.olddiffout

	diffout = []
	newlist = []

	# Match things not in old (new hosts)
	
	for object in a:
		if "." in object:
			ma = 0
			for item in b:
				if object == item:
					ma = 1
					newlist.append(str(object))
			if ma == 0:
				g = 0
				for thing in a:
					if g == 1:
						if "." in thing:
							g = 3
							pass
						else:
							diffout.append(str(thing) + " FIREWALL-OPEN")
							statics.numopen = statics.numopen + 1
					if object is thing:
						diffout.append(str(object) + " NEW-HOST")
						statics.newlivehosts = statics.newlivehosts + 1
						g = 1		
	
	# Match things not in new (old hosts)

	for object in b:
		if "." in object:
			ma = 0
			for item in a:
				if object == item:
					ma = 1
			if ma == 0:
				g = 0
				for thing in b:
					if g == 1:
						if "." in thing:
							g = 3
							pass
						else:
							diffout.append(str(thing) + " FIREWALL-CLOSED")
							statics.numclosed = statics.numclosed + 1
					if object is thing:
						diffout.append(str(object) + " OLD-HOST")
						statics.oldlivehosts = statics.oldlivehosts + 1
						g = 1		
	
	# Get data for existing ips (present in both)

	tempbuf1 = []
	tempbuf2 = []
	for object in newlist:
		diffout.append(object)
		ma = 0
		for item in a:
			if ma == 1:
				if "." in item:
					pass
					ma = 0
				else:
					tempbuf1.append(item)
			if "." in item:	
				if object == item:
					tempbuf1.append(object)				
					ma = 1	
		ma = 0		
		for item in b:
			if ma == 1:
				if "." in item:
					pass
					ma = 0
				else:
					tempbuf2.append(item)
			if "." in item:	
				if object == item:
					tempbuf2.append(object)				
					ma = 1
		
		# Compare to see whats new (open)
		n = 0
		for item in tempbuf1:
			g = 0
			if "." in item:
				pass
			else:
				for thing in tempbuf2:
					if "." in thing:				
						pass					
					else:
						item1 = item.replace(" closed","")
						item2 = item1.replace(" open","")
						item3 = item2.replace(" udp","")
						item4 = item3.replace(" tcp","")
						thing1 = thing.replace(" open","")
						thing2 = thing1.replace(" closed","")
						thing3 = thing2.replace(" udp","")
						thing4 = thing3.replace(" tcp","")

						if item4 == thing4:
							g = 1
							if "closed" in item:
								if "open" in thing:
									g = 2
							if "open" in item:
								if "closed" in thing:
									g = 3
		
				if g == 0:
					diffout.append(str(item) + " FIREWALL-OPEN")
					statics.numopen = statics.numopen + 1
					n = 1
				if g == 2:
					diffout.append(str(item) + " PORT-CLOSED")
					n = 1
				if g == 3:
					diffout.append(str(item) + " PORT-OPEN")
					statics.numopen = statics.numopen + 1
					n = 1

					

		# Compare to see whats old (closed)

		for item in tempbuf2:
			g = 0
			if "." in item:
				pass
			else:
				for thing in tempbuf1:
					if "." in thing:				
						pass					
					else:
						item1 = item.replace(" closed","")
						item2 = item1.replace(" open","")
						item3 = item2.replace(" udp","")
						item4 = item3.replace(" tcp","")
						thing1 = thing.replace(" open","")
						thing2 = thing1.replace(" closed","")
						thing3 = thing2.replace(" tcp","")
						thing4 = thing3.replace(" udp","")

						if item4 == thing4:
							g = 1
				if g == 0:
					diffout.append(str(item) + " FIREWALL-CLOSED")
					statics.numclosed = statics.numclosed + 1
					n = 1	
	
		if n == 0:
			del diffout[len(diffout) - 1]
		tempbuf1 = []
		tempbuf2 = []

	statics.diffout = diffout

	#print diffout
	statics.difffilename = "/var/log/watcher/" + statics.scanname + "/" + str(statics.day) + "-" + "diff.log"
	file = open(statics.difffilename, 'w')
	
	s = len(diffout)
	k = 0
	while k < s:
		if k == 0:
			file.write("<HTML><BODY><PRE>")
			file.write("NEW HOST = Host that had no open ports in previous scan but has in current. \n")
			file.write("OLD HOST = Host that had open ports in previous scan but has only closed in current. \n")
			file.write("If IP does not have either, device has firewall port changes in previous and current. \n")

		ch = diffout[k].split(" ")
		if "." in ch[0]:
			file.write("\n")
			try:
				file.write('%-15s %-15s %-25s %-15s %-15s\n' % (ch[0], '', '', '', ch[1]))
			except:
				file.write('%-15s %-15s %-25s %-15s %-15s\n' % (ch[0], '', '', '', ''))
		else:
			file.write('%-15s %-15s %-15s %-20s %-15s\n' % (ch[0], ch[2], ch[1], ch[3], ch[4]))
		k = k + 1
		if k == s:
			file.write("</PRE></BODY></HTML>")
	file.close()
	
	string = "cp " + statics.filename + " " + statics.scanname + "-prev.gnmap"
	os.system(string)

	a = statics.newdiffout
	file = "/var/log/watcher/" + statics.scanname + "/" + "ips.txt"
	out = open(file, 'w')
	for object in a:
		if "." in object:
			out.write(str(object) + "\n")

	out.close()	
	return
			
def stats():															# Function to process graph stats

	print "Processing stats...."
	
	# Output stats
	
	file = "/var/log/watcher/" + statics.scanname + "/" + "stats.log"
	out = open(file, 'a+')

	output = str(statics.newlivehosts) + "," + str(statics.oldlivehosts) + "," + str(statics.numclosed) + "," + str(statics.numopen) + "\n"
	out.write(output)
	out.close()

	#Input stats
	
	inp = open(file,'r')
	for line in inp:
		xx = line
		xx = xx.strip('\n')
		cc = re.split(',', xx)
		statics.graphlivenew.append(int(cc[0]))
		statics.graphliveold.append(int(cc[1]))
		statics.graphclosed.append(int(cc[2]))
		statics.graphopen.append(int(cc[3]))	
	inp.close()
	statics.graphclosed = [ -x for x in statics.graphclosed]
	statics.graphclosed = statics.graphclosed[-30:]
	statics.graphopen = statics.graphopen[-30:]
	statics.graphlivenew = statics.graphlivenew[-30:]
	statics.graphliveold = statics.graphliveold[-30:]
	statics.graphliveold = [ -x for x in statics.graphliveold]
	return
	
def graph():															# Function to generate graphs
	
	print "Generating graphs...."		
	
	# Output port change graph
	
	filename = "/var/log/watcher/" + statics.scanname + "/" + "ports.jpg"		
	x = range(len(statics.graphopen))
	fig = plt.figure()
	ax = plt.subplot(111)
	ax.set_xlim([0,len(statics.graphopen)])
	ax.bar(x, statics.graphclosed, width=1, color='r')
	ax.bar(x, statics.graphopen, width=1, color='b')
	plt.ylabel('Firewall Port Changes')
	plt.xlabel('Scans')
	te = str(statics.scanname + " Ports")
	plt.title(te)
	plt.savefig(filename, format='jpg', dpi=100)
	plt.close

	# Output host change graph

	filename = "/var/log/watcher/" + statics.scanname + "/" + "hosts.jpg"
	plt.cla()
	x = range(len(statics.graphlivenew))
	fig = plt.figure()
	ax = plt.subplot(111)
	ax.set_xlim([0,len(statics.graphlivenew)])
	ax.bar(x, statics.graphlivenew, width=1, color='b')
	ax.bar(x, statics.graphliveold, width=1, color='r')
	plt.ylabel('Host Changes')
	plt.xlabel('Scans')
	te = str(statics.scanname + " Hosts")
	plt.title(te)
	plt.savefig(filename, format='jpg', dpi=100)
	plt.close

	return
	
def mail():																# Function to send output	
	
	if statics.change == 0:
		print "Change!.. Mail Sent"
		comm = 'mutt -e "set content_type=text/html" -s ' + '"' + "SIRTWatcher - " + statics.scanname + " Change" + '" ' + statics.recipients + " -a /var/log/watcher/" + statics.scanname + "/ports.jpg" + " -a /var/log/watcher/" + statics.scanname + "/hosts.jpg " + "-a /var/log/watcher/" + statics.scanname + "/ips.txt " + "-- < " + statics.difffilename
		os.system(comm)
	else:
		print "No change.."
	print "Done..."
	return
			
if __name__ == '__main__':					# Main
	
	statics()															# Initialize global variables
	config()															# Process config file
	scan()																# Execute scan
	process(statics.filename, "new")			# process todays scans
	process(statics.prevfile, "old")			# process yesterdays scans
	compare()                             # work out differenc
	stats()																# input/output graph stats
	graph()																# generate graphs
	mail()																# email output
	
