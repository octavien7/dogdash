from scapy.all import *
from twilio.rest import TwilioRestClient
import time

account_sid = "AC8a2dfaba720a292bbdc4fb953e8434cd" # Your Account SID from www.twilio.com/console
auth_token  = "8c3bfb8b0b556781833cf744a69f4489"  # Your Auth Token from www.twilio.com/console
client = TwilioRestClient(account_sid, auth_token)

def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      if pkt[ARP].hwsrc == '74:c2:46:fc:f7:ce': # Dash button
        print "Pushed ON Dash Button! Now sending text"d
    time_var = 'Dogs were fed at ' + time.strftime("%a %b %d %Y %H:%M:%S %p")

    message = client.messages.create(body=time_var,
          to="+17036566048",    # Replace with your phone number
          from_="+17036596930") # Replace with your Twilio number

        #print(message.sid)
      else:
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(prn=arp_display, filter="arp", store=0, count=10)
