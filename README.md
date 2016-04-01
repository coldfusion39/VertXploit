# VertXploit
HID VertX/Edge Command Injection

## Summary ##
Originally disclosed by Ricky "HeadlessZeke" Lawshae of Trend Micro DVLabs

This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of HID Edge. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the discoveryd service. The issue lies in the failure to sanitize user data before executing a system call. An attacker could leverage this vulnerability to execute code with root privileges.

The actual location of the command injection is in the `command_blink_on` command. Normally, the command would end with the number of times the VertX/Edge controller light should blink, in this case 30 times. 

`command_blink_on;042;<MAC_ADDRESS>;30;`

By replacing the number of blinks with a Linux command and wrapping it in back ticks, the command will get executed by the controller.

``command_blink_on;042;<MAC_ADDRESS>;`ping -c 5 192.168.0.39`;``

## Usage ##
The only requirement is the IP address of an un-patched HID VertX/Edge door controller. The device itself uses UDP port 4070 by default. Depending on what payload is being sent, the VertX/Edge system may not be able to execute the command because it is not installed (ie Python, PERL, ruby, etc). As a simple proof of concept, the Linux 'ping' command seems to work on all VertX/Edge models tested.

## Example ##
###### Execute the command 'ping -c 5 192.168.0.39'

`python vertXploit.py -i 192.168.0.5 ping -c 5 192.168.0.39`

## Resources ##
* TrendMicro Blog - http://blog.trendmicro.com/let-get-door-remote-root-vulnerability-hid-door-controllers/
* ZDI - http://www.zerodayinitiative.com/advisories/ZDI-16-223/
* Other Work - http://nosedookie.blogspot.com/2011/07/identifying-and-querying-hid-vertx.html

