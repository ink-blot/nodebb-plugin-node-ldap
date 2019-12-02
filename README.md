# NodeBB LDAP Authentication Plugin

This plugin was modified from https://github.com/smartameer/nodebb-plugin-office-ldap to allow for authentication using an OpenLDAP server.

The plugin allows a user to log in to NodeBB using credentials stored in the LDAP server. If the user doesn't currently exist in NodeBB, it will be created using the details retrieved from the LDAP server. Once installed, settings can be changed within the 'LDAP settings' menu in the 'Plugins' tab of the ACP (you may need to refresh the page for the tab to become visible).

Please disable user registration in the NodeBB ACP (Settings>User>User Registraion>No Registration) when using this plugin.

Features of the plugin include:

* can log in to NodeBB via an email address or an additional 'Filter' field (Plugins>LDAP settings>Filter) that is stored in the LDAP server.
* the email field MUST be set for each user in the LDAP server as the 'Filter' field is merely used to retrieve the email field for subsequent authentication.
* on first login the username within NodeBB is generated from the 'User Name' field chosen in the 'LDAP settings' menu and retrieved from the LDAP server (must be unique for each user).
* on first login the user 'Full Name' in NodeBB is generated using the 'Given Name' and 'Surname' fields  chosen in the 'LDAP settings' menu and retrieved from the LDAP server.

## Installation
The easiest way to install the plugin is via the Admin Control Panel (ACP - located at https://your.domain.name/admin/). Navigate to Plugins>Install Plugins>Find Plugins and search for 'nodebb-plugin-node-ldap'. Install the plugin, activate it and rebuild and restart NodeBB using the ACP Dashboard. Alternatively, the plugin can be manually installed from the command line as follows:
```
npm install nodebb-plugin-node-ldap
```
It is possible that your linux distribution may be missing some dependencies for this plugin to work. If that is the case, try:
```
sudo apt-get update && apt-get install -y ldap-utils dnsutils
```
## Screenshots

### Desktop
![Desktop OfficeLDAP](screenshots/desktop.png?raw=true)
