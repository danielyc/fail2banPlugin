# Fail2Ban Security Plugin for CyberPanel 🛡️

Enhance your web server's security with comprehensive brute force attack protection that's easy to configure and maintain.

## Features

- 🔒 Secure your websites against brute force attacks
- ⚙️ Intuitive web interface for managing Fail2Ban configurations
- 🕒 Customizable ban times, retry limits, and monitoring windows
- 📊 Domain-specific security policies
- ⚪ IP whitelist support for trusted addresses
- 🔄 Automatic configuration file generation
- 🚫 Protection for website backends and CyberPanel admin login

## Prerequisites

- CyberPanel installed and running
- Administrator access to your server

## Installation

1. Install the plugin through the CyberPanel plugin manager (/usr/local/CyberCP/pluginInstaller/pluginInstaller.py)
2. The plugin will automatically check if Fail2Ban is installed
3. If not installed, use the provided one-click installer
4. Access the plugin through the Plugins section in CyberPanel

## Usage

1. Navigate to Plugins -> fail2banPlugin
2. Select a domain from the dropdown menu
3. Configure protection parameters:
   - Maximum retry attempts before banning
   - Time window to monitor
   - Ban duration for offending IPs
   - HTTP status codes to monitor
   - Whitelist trusted IP addresses
4. Click "Create Configuration" or "Update Configuration" to activate protection
5. Review existing configurations in the table view

## Advanced Configuration

- The plugin automatically generates proper jail and filter configurations
- Configurations target common web attack patterns
- Custom HTTP status code monitoring for precise security rules
- IP whitelisting supports both individual IPs and CIDR notation

## Troubleshooting

- Verify Fail2Ban service is running with `systemctl status fail2ban`
- Check system logs at `/var/log/fail2ban.log` for ban activity
- Review your configuration file generated at `/etc/fail2ban/jail.d/yourdomain.conf`
- Ensure proper log paths are configured for accurate monitoring
