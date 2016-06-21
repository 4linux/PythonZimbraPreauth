#!/usr/bin/python

from flask import Flask,render_template,request,redirect,jsonify
import ldap
from hashlib import sha1
import ConfigParser
from datetime import datetime
from datetime import date
from datetime import time as time_convert
import hmac
import time
import subprocess
import os

app = Flask(__name__)

class Iptables:
    # Class created to allow a connection to zimbra
    # by the incoming address for a specific user
	def __init__(self,email,remote_addr):
		self.email = email
		self.remote_addr = remote_addr

	def allow_login(self):
		iptables_cmd = "sudo /sbin/iptables -t nat -I PREROUTING  -m multiport -m comment -s %s -p tcp --dport 80,443,7071 --comment '%s' -j ACCEPT"%(self.remote_addr,self.email)
		try:
			print subprocess.Popen([iptables_cmd],shell=True)
			return True
		except Exception as e:
			print "Error: ",e
			return False

	def deny_login(self,line):
		iptables_cmd = "sudo /sbin/iptables -t nat -D PREROUTING  %s"%(line)
		try:
			print subprocess.Popen([iptables_cmd],shell=True)
			return True
		except Exception as e:
			print "Error: ",e
			return False

		

class ZimbraAuth:
    def __init__(self):
        # Get config of zimbra in file
        config = ConfigParser.ConfigParser()
        config.read(os.path.dirname(os.path.abspath(__file__))+"/ldap.cfg")
        self.domain = config.get("zimbra","domain")
        self.preauth_key = config.get("zimbra","preauth_key")

    def generateAuth(self,account):
		expires = 0
		timestamp = int(time.mktime(datetime.now().timetuple()))*1000
		by = "name"
		string = "%s|%s|%s|%s"%(account,by,expires,timestamp)

        # Genereate hash for zimbra preauth
		pre = hmac.new(self.preauth_key,string,sha1).hexdigest()		

		return "https://%s/service/preauth?account=%s&expires=%s&timestamp=%s&preauth=%s"%(self.domain,account,expires,timestamp,pre)


class Ldap:
    def __init__(self,user,password):
        try:
            config = ConfigParser.ConfigParser()
            config.read(os.path.dirname(os.path.abspath(__file__))+"/ldap.cfg")
            self.address = config.get("ldap","server")
            self.user = user
            self.password = password
            self.base = config.get("ldap","base")
            self.connection = ldap.initialize("ldap://%s"%self.address)
            self.connection.protocol_version = ldap.VERSION3
            ldap_filter = '(mail=%s)'%self.user
            dn = self.connection.search_s(self.base,ldap.SCOPE_SUBTREE,ldap_filter)[0][0]
            self.connection.bind_s(dn,self.password)
        except Exception as e:
            print "Error: ",e
	    raise
        except ldap.LDAPError as e:
            print "Error in ldap: ",e
	    raise

    def search_user(self,email,remote_addr):
		ldap_filter = '(&(mail=%s)(description=*))'%email
		res = self.connection.search_s(self.base,ldap.SCOPE_SUBTREE,ldap_filter,['description'])
		print res
		if res:
			account_status = "sudo /opt/zimbra/bin/zmprov ga %s zimbraAccountStatus"%(email)
			print account_status
			status = subprocess.Popen([account_status],shell=True,stdout=subprocess.PIPE).communicate()[0]
			print status
			if "locked" in status:
				return "Usu&aacute;rio fora do expediente permitido!"
			ipt = Iptables(email,remote_addr)
			ipt.allow_login()
			z = ZimbraAuth()
			return z.generateAuth(email)
		else:
			return "Usu&aacute;rio sem acesso externo permitido!"


@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login",methods=["GET","POST"])
def login():
	try:
        # If request method is post
        # make login in interface
		if request.method == "POST":
			email = request.form['email']
			password = request.form['password']
			print "ENDERECO REMOTO: ",request.remote_addr
            # login in ldap with credentials
			l = Ldap(email,password)
			res = l.search_user(email,request.remote_addr)
            # if return is string, show error message
			if type(res) is str:
				return jsonify({"message":res})
			else:
                # make preauth
				return jsonify({"message":"Aguarde, fazendo login","url":res})
		else:
			return jsonify({"message":"Metodo GET"})

	except Exception as e:
		print "Falhou ",e
		return jsonify({"message":"Usu&aacute;rio ou Senha inv&aacute;lida!"})

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0")
