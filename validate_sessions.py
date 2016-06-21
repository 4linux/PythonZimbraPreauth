#!/usr/bin/python

import subprocess
from xml.etree import ElementTree
import sys
import time
import ConfigParser
from run import Iptables
import os
import ldap
from datetime import datetime
from datetime import time as time_convert
from datetime import date
import requests
import hmac
from hashlib import sha1
import time as time_sleep

class Ldap:
    # Class created to connect with ldap
    def __init__(self):
        try:
            # instance of config parser to read configurations of ldap.cfg
            config = ConfigParser.ConfigParser()
            config.read(os.path.dirname(os.path.abspath(__file__))+"/ldap.cfg")
            self.address = config.get("ldap","server")
            self.user = config.get("ldap","user")
            self.password = config.get("ldap","password")
            self.base = config.get("ldap","base")
            self.connection = ldap.initialize("ldap://%s"%self.address)
            self.connection.protocol_version = ldap.VERSION3
            self.connection.bind(self.user,self.password)

        except Exception as e:
            print "Error: ",e
        except ldap.LDAPError as e:
            print "Error in ldap: ",e


    def list_restricted_users(self):
        # ldap filter
        ldap_filter = '(description=*)'

        # execute ldap search for all substrees in base and returnin
        # description and mail attributes
        res = self.connection.search_s(self.base,
                                       ldap.SCOPE_SUBTREE,
                                       ldap_filter,
                                       ['description','mail'])

	    locked_users = []
	    active_users =  []

	    for r in res:
		    if "admin" in r[0]:
			    continue
            # get current day of week
            today = datetime.today().weekday()

            # get current date and time
            now = datetime.now()

            # create a list with access rules
            access_rule = r[1].get("description")[0].split(";")

            # get user email from ldap
		    email = r[1].get("mail")[0]
		    for a in access_rule:
                # tuple of start day and end day
		        start_day,end_day = a.split(":")[0].split("-")

                # tuple of start hour and minute
		        start_hour,start_minute = a.split(":")[1].split(".")

                # tuple o end hour and minute
		        end_hour,end_minute = a.split(":")[2].split(".")

                # store the start time of user can access zimbra
		        start_time = time_convert(int(start_hour),int(start_minute))

                # store the end time
		        end_time = time_convert(int(end_hour),int(end_minute))

                # verify if current date and time is beetween access rule
		        if not int(start_day) <= date.today().weekday() <= int(end_day) or \
                   not start_time <= datetime.now().time() <= end_time:
                            if email not in locked_users:
            	                locked_users.append(email)
		        else:
    			    if email not in active_users:
                            active_users.append(email)

        # return tuple with 2 lists, the first with users to block access
        # and the second with users to activate
	    return (locked_users, active_users)



def block_users():
    # This function execute zimbra commands to lock or active users in zimbra

	l = Ldap()
	locked, actives = l.list_restricted_users()

    # lock users that are not in expedient
	for u in locked:
		account_status = "sudo /opt/zimbra/bin/zmprov ga %s zimbraAccountStatus"%(u)
		status = subprocess.Popen([account_status],
                                  shell=True,
                                  stdout=subprocess.PIPE).communicate()[0]
		if not "locked" in status:
		    account_status = "sudo /opt/zimbra/bin/zmprov ma %s zimbraAccountStatus locked"%(u)
		    status = subprocess.Popen([account_status],
                                      shell=True,
                                      stdout=subprocess.PIPE).communicate()[0]

    # active users
	for u in actives:
		account_status = "sudo /opt/zimbra/bin/zmprov ga %s zimbraAccountStatus"%(u)
		status = subprocess.Popen([account_status],
                                  shell=True,
                                  stdout=subprocess.PIPE).communicate()[0]
		if not "active" in status:
		    account_status = "sudo /opt/zimbra/bin/zmprov ma %s zimbraAccountStatus active"%(u)
		    status = subprocess.Popen([account_status],
                                      shell=True,
                                      stdout=subprocess.PIPE).communicate()[0]



def get_allowed_users():
    # This functions return a list with email of users allowed in iptables
    # For each user allowed to access zimbra webmail, is created a iptables rule
    # with the user email

	users = []
	iptables_cmd = "sudo /sbin/iptables -L -n -t nat"

    # execute an iptables command
	users_allowed = subprocess.Popen([iptables_cmd],
                                     shell=True,
                                     stdout=subprocess.PIPE).communicate()

    # for each result the email is stored in a list
	for u in users_allowed[0].split("\n"):
		if "@" in u:
			begin = u.index("/*")
			end = u.index("*/")
			user = u[begin+2:end].replace(" ","")
			users.append(user)

    # list is returned for analysis
	return users


def get_active_users():
    # This function get all users current logged in Zimbra
	users = []

    # The command on bellow shows the users current logged in zimbra
	get_sessions_cmd = "sudo /opt/zimbra/bin/zmsoap -z -t admin -v DumpSessionsRequest @groupByAccount=1 @listSessions=1"
	logged_users = subprocess.Popen([get_sessions_cmd],
                                    shell=True,
                                    stdout=subprocess.PIPE).communicate()

    # Parsing XML returned by zimbra
	xml = logged_users[0].split("\n")
	xml = "".join(xml[1:])
	root = ElementTree.fromstring(xml)
	for c in root:
		for i in c:
			users.append(i.attrib.get("name"))
	return users

def remove_not_actives(users):
    # This function removes iptables rules that allow users to access Zimbra
	if type(users) is list:
		for u in users:
            # Get iptables rules
			iptables_cmd = "sudo /sbin/iptables -t nat -L -n --line-numbers | grep %s | awk '{print $1 }'"%u
			remove_user = subprocess.Popen([iptables_cmd],
                                            shell=True,
                                            stdout=subprocess.PIPE) \
                                            .communicate()

            # remove rules on iptables
			for rule_line in remove_user[0].split("\n"):
				if rule_line:
					iptables_cmd = "sudo /sbin/iptables -t nat -D PREROUTING %s"%rule_line
					remove_rule = subprocess.Popen([iptables_cmd],
                                                    shell=True,
                                                    stdout=subprocess.PIPE) \
                                                    .communicate()
	else:
		# Remove iptables rules for users out of expedient
		iptables_cmd = "sudo /sbin/iptables -t nat -L -n --line-numbers | grep %s | awk '{print $1 }'"%users
		remove_user = subprocess.Popen([iptables_cmd],
                                        shell=True,
                                        stdout=subprocess.PIPE).communicate()

        # run command for each result
		for rule_line in remove_user[0].split("\n"):
			if rule_line:
				iptables_cmd = "sudo /sbin/iptables -t nat -D PREROUTING %s"%rule_line
				remove_rule = subprocess.Popen([iptables_cmd],
                                                shell=True,
                                                stdout=subprocess.PIPE) \
                                                .communicate()


def verify_zimbra(email):
    # this function verify status of a zimbra account
	account_status = "sudo /opt/zimbra/bin/zmprov ga %s zimbraAccountStatus"%(email)
	status = subprocess.Popen([account_status],
                              shell=True,
                              stdout=subprocess.PIPE).communicate()[0]
	if "locked" in status:
		remove_not_actives(email)



try:
    # Main function
    # Blocking users out of expedient
	block_users()
	alloweds = get_allowed_users()
	print "Alloweds ",alloweds
	actives = get_active_users()
	print "Actives ",actives
	remove = [ user for user in alloweds if user not in actives ]
    # Remove users that are in expedient but are not logged in
    # and has an iptables rule
	remove_not_actives(remove)
	for a in alloweds:
		verify_zimbra(a)

except Exception as e:
	print "Erro: ",e
