# Python Zimbra Preauth

Python Zimbra Preauth is a Flask Application that manages external access to Zimbra.

The management is made using IPTables rules and OpenLdap.

If a user wants to access the Zimbra Webmail, he needs to have a ldap attribute called *description*, with weekday and hour to access the webmail.

This attribute description, needs to follow the example on below:
0-4:1800:2200

Explaining this.

The rules are separated by colon ( : ), the first part is the days of week, it describes which days an user can access the Zimbra Webmail:

The days of week is defined by the following numbers:
* 0 - Monday
* 1 - Tuesday
* 2 - Wednesday
* 3 - Thursday
* 4 - Friday
* 5 - Saturday
* 6 - Sunday

Second part is the start hour, and the last is the end hour. 

For example:

A user can access between 9 am to 6 pm, the rule need to be in the follows format:

 0900:1800

If the current date and current hour match with the rule in the attribute description of user in ldap, the aplication will add an iptables rule granting the access and the user will be redirected to Zimbra using preauth method.



# Setup application
Dependencies of Linux:

apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev python-ldap

Install python modules:

pip install -r requirements.txt

Create user to run application

adduser devops

Give to user a sudo permission with no passwd:

visudo 
devops ALL=(ALL) ALL:NOPASSWD

Add a line in crontab to validate sessions

crontab -e
*/5 * * * * /srv/WebmailBlock/validade_sessions.py > /dev/null 2>&1

Rules to block access:
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 5000
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 5443

# Run Application

python run.py



 


