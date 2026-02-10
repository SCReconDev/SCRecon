# SCRecon 

SCRecon is an extensible recon & vulnerability management tool.

## Setup:

### Linux:

From this folder, build the project by running:
```bash
sudo docker compose build
```

Then run the project with:
```bash
sudo docker compose up
```

### Windows:

First, start a command line with admin permissions.

From this folder, build the project by running:
```cmd
docker compose build
```

Then run the project with:
```cmd
docker compose up
```

## Usage:
Open the web-interface in your browser at: 
```
http://127.0.0.1:8080
```

Make sure that the browser window keeps running while a scan is active!

# Target:

To set up a target to test SCRecon, we recommend the Metasploitable 2 VM by Rapid7. 

Download it here:

```
https://www.rapid7.com/products/metasploit/metasploitable/
```

Then import it using VMWare Workstation / Fusion.

Start the VM, log in with the credentials msfadmin / msfadmin.

Run ifconfig to see the IPv4 address of the VM.

Then start an SCRecon scan targeting this IP address.

If the scan does not reach the target VM, set its network adapter to bridged mode.
