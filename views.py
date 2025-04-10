import json
import os
import subprocess
from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse
from plogical.acl import ACLManager
import plogical.CyberCPLogFileWriter as logging
from plogical.processUtilities import ProcessUtilities
from loginSystem.views import loadLoginPage
from websiteFunctions.models import Websites
from .models import Fail2BanConfig

# Path to check for fail2ban installation
FAIL2BAN_CLIENT_PATH = '/usr/bin/fail2ban-client'

def get_domains(userID):
    """
    Get list of all main domains from the server (excludes subdomains)
    """
    try:
        currentACL = ACLManager.loadedACL(userID)
        websitesName = ACLManager.findAllSites(currentACL, userID)
        websitesName.append("CyberPanel")
        # No longer including child domains since they don't need separate configs
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"get_domains: {websitesName}")
        return websitesName
    except Exception as e:
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"get_domains: {str(e)}")
        return []

def fail2banPlugin(request):
    """
    Main plugin view that serves as an entry point or dashboard for the Fail2Ban Plugin.
    """
    try:
        userID = request.session['userID']
        currentACL = ACLManager.loadedACL(userID)

        if ACLManager.currentContextPermission(currentACL, 'adminTools') == 0:
            return ACLManager.loadError()
        
        # Check if fail2ban is installed
        fail2ban_installed = os.path.exists(FAIL2BAN_CLIENT_PATH)
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"fail2banPlugin: fail2ban_installed: {fail2ban_installed}")
        # Get all domains
        domains = get_domains(userID)
        
        # Get existing configurations
        configs = Fail2BanConfig.objects.all()
        
        # Convert QuerySet to list of dictionaries for JSON serialization
        configs_list = []
        for config in configs:
            configs_list.append({
                'domain': config.domain,
                'max_retries': config.max_retries,
                'find_time': config.find_time,
                'ban_time': config.ban_time,
                'status_codes': config.status_codes,
                'ip_whitelist': config.ip_whitelist
            })
        
        # Convert domains to list if it's not already
        domains_list = list(domains) if not isinstance(domains, list) else domains
        
        import json
        return render(request, 'fail2banPlugin/fail2banConfig.html', {
            'adminTools': 1,
            'fail2banContext': 1,
            'fail2ban_installed': 'true' if fail2ban_installed else 'false',
            'domains': json.dumps(domains_list),
            'configs': json.dumps(configs_list)
        })
    except KeyError:
        return redirect(loadLoginPage)

def install_fail2ban(request):
    """
    Install fail2ban on the server
    """
    if request.method != 'POST':
        return JsonResponse({'status': 0, 'error_message': 'Only POST requests are allowed.'}, status=405)

    try:
        # Install fail2ban
        if os.path.exists('/etc/debian_version'):
            # Debian/Ubuntu
            install_cmd = 'apt-get update && apt-get install -y fail2ban'
        elif os.path.exists('/etc/redhat-release'):
            # CentOS/RHEL
            install_cmd = 'yum install -y epel-release && yum install -y fail2ban'
        else:
            return JsonResponse({'status': 0, 'error_message': 'Unsupported operating system'}, status=500)

        # Execute the command
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"install_fail2ban command: {install_cmd}")
        success = ProcessUtilities.executioner(install_cmd, None, True)
        
        # In some versions, executioner returns only exitCode, in others (exitCode, output)
        if success:
            # Enable and start fail2ban service
            enableResult = ProcessUtilities.executioner('systemctl enable fail2ban', None, True)
            startResult = ProcessUtilities.executioner('systemctl start fail2ban', None, True)
            if os.path.exists(ProcessUtilities.debugPath):
                logging.CyberCPLogFileWriter.writeToFile(f"Enable fail2ban result: {enableResult}")
                logging.CyberCPLogFileWriter.writeToFile(f"Start fail2ban result: {startResult}")
            return JsonResponse({'status': 1, 'message': 'Fail2Ban installed successfully'}, status=200)
        else:
            return JsonResponse({'status': 0, 'error_message': f'Failed to install Fail2Ban'}, status=500)

    except Exception as e:
        return JsonResponse({'status': 0, 'error_message': f'An unexpected error occurred: {str(e)}'}, status=500)

def create_fail2ban_config(request):
    """
    Create or update a fail2ban configuration for a domain
    """
    if request.method != 'POST':
        return JsonResponse({'status': 0, 'error_message': 'Only POST requests are allowed.'}, status=405)

    try:
        # Extract parameters from POST data
        domain = request.POST.get('domain')
        max_retries = int(request.POST.get('max_retries', 30))
        find_time = int(request.POST.get('find_time', 60))
        ban_time = int(request.POST.get('ban_time', 300))
        status_codes = request.POST.get('status_codes', '401,403,404,500')
        ip_whitelist = request.POST.get('ip_whitelist', '')

        if not domain:
            return JsonResponse({'status': 0, 'error_message': 'Domain is required.'}, status=400)

        # Create or update the configuration in the database
        config, created = Fail2BanConfig.objects.update_or_create(
            domain=domain,
            defaults={
                'max_retries': max_retries,
                'find_time': find_time,
                'ban_time': ban_time,
                'status_codes': status_codes,
                'ip_whitelist': ip_whitelist
            }
        )

        # Generate the configuration content
        jail_content = generate_jail_config(config)
        filter_content = generate_filter_config(config)
        
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"create_fail2ban_config: jail_content: {jail_content}")
            logging.CyberCPLogFileWriter.writeToFile(f"create_fail2ban_config: filter_content: {filter_content}")
            
        # Create temporary files
        import tempfile
        temp_jail_file = tempfile.NamedTemporaryFile(delete=False)
        temp_filter_file = tempfile.NamedTemporaryFile(delete=False)
        
        try:
            # Write content to temporary files
            with open(temp_jail_file.name, 'w') as f:
                f.write(jail_content)
                
            with open(temp_filter_file.name, 'w') as f:
                f.write(filter_content)
                
            # Define target paths
            jail_path = f'/etc/fail2ban/jail.d/{domain}.conf'
            filter_path = f'/etc/fail2ban/filter.d/{domain}.conf'
            
            # Use ProcessUtilities to copy files with proper permissions
            jail_copy_cmd = f'cp {temp_jail_file.name} {jail_path}'
            filter_copy_cmd = f'cp {temp_filter_file.name} {filter_path}'
            
            # Execute copy commands
            jail_copy_result = ProcessUtilities.executioner(jail_copy_cmd, None, True)
            filter_copy_result = ProcessUtilities.executioner(filter_copy_cmd, None, True)
            
            if os.path.exists(ProcessUtilities.debugPath):
                logging.CyberCPLogFileWriter.writeToFile(f"Copy jail config result: {jail_copy_result}")
                logging.CyberCPLogFileWriter.writeToFile(f"Copy filter config result: {filter_copy_result}")
                
            # Set proper permissions
            perm_cmd = f'chmod 644 {jail_path} {filter_path}'
            perm_result = ProcessUtilities.executioner(perm_cmd, None, True)
            
            if os.path.exists(ProcessUtilities.debugPath):
                logging.CyberCPLogFileWriter.writeToFile(f"Set permissions result: {perm_result}")
        
        finally:
            # Clean up temporary files
            os.unlink(temp_jail_file.name)
            os.unlink(temp_filter_file.name)

        # Reload fail2ban to apply the new configuration
        reload_result = ProcessUtilities.executioner('fail2ban-client reload', None, True)
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"Reload fail2ban result: {reload_result}")

        return JsonResponse({
            'status': 1, 
            'message': f'Configuration for {domain} has been created/updated successfully',
            'config_id': config.id
        }, status=200)

    except Exception as e:
        return JsonResponse({'status': 0, 'error_message': f'An unexpected error occurred: {str(e)}'}, status=500)

def get_fail2ban_status(request):
    """
    Get the status of a fail2ban configuration for a domain
    """
    if request.method != 'GET':
        return JsonResponse({'status': 0, 'error_message': 'Only GET requests are allowed.'}, status=405)
    
    try:
        # Extract domain from request
        domain = request.GET.get('domain')
        
        if not domain:
            return JsonResponse({'status': 0, 'error_message': 'Domain is required.'}, status=400)
            
        # Execute fail2ban-client status command
        status_cmd = f'fail2ban-client status {domain}'
        result = ProcessUtilities.outputExecutioner(status_cmd, None, True)
        
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"Get fail2ban status result: {result}")
            
        # Format the output for better display
        formatted_output = result.replace('\n', '<br>')
            
        return JsonResponse({
            'status': 1, 
            'message': f'Status for {domain}',
            'statusOutput': formatted_output
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'status': 0, 'error_message': f'An unexpected error occurred: {str(e)}'}, status=500)
        

def delete_fail2ban_config(request):
    """
    Delete a fail2ban configuration for a domain
    """
    if request.method != 'POST':
        return JsonResponse({'status': 0, 'error_message': 'Only POST requests are allowed.'}, status=405)

    try:
        # Extract domain from POST data
        domain = request.POST.get('domain')

        if not domain:
            return JsonResponse({'status': 0, 'error_message': 'Domain is required.'}, status=400)

        # Delete the configuration from the database
        try:
            config = Fail2BanConfig.objects.get(domain=domain)
            config.delete()
        except Fail2BanConfig.DoesNotExist:
            return JsonResponse({'status': 0, 'error_message': f'No configuration found for {domain}'}, status=404)

        # Remove the configuration files
        jail_path = f'/etc/fail2ban/jail.d/{domain}.conf'
        filter_path = f'/etc/fail2ban/filter.d/{domain}.conf'
        
        # Use ProcessUtilities to remove files that require elevated permissions
        jail_remove_cmd = f'rm -f {jail_path}'
        filter_remove_cmd = f'rm -f {filter_path}'
        
        jail_remove_result = ProcessUtilities.executioner(jail_remove_cmd, None, True)
        filter_remove_result = ProcessUtilities.executioner(filter_remove_cmd, None, True)
        
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"Remove jail config result: {jail_remove_result}")
            logging.CyberCPLogFileWriter.writeToFile(f"Remove filter config result: {filter_remove_result}")

        # Reload fail2ban to apply the changes
        reload_result = ProcessUtilities.executioner('fail2ban-client reload', None, True)
        if os.path.exists(ProcessUtilities.debugPath):
            logging.CyberCPLogFileWriter.writeToFile(f"Reload fail2ban result: {reload_result}")

        return JsonResponse({'status': 1, 'message': f'Configuration for {domain} has been deleted successfully'}, status=200)

    except Exception as e:
        return JsonResponse({'status': 0, 'error_message': f'An unexpected error occurred: {str(e)}'}, status=500)

def get_fail2ban_config(request):
    """
    Get the fail2ban configuration for a domain
    """
    if request.method != 'GET':
        return JsonResponse({'status': 0, 'error_message': 'Only GET requests are allowed.'}, status=405)

    try:
        # Extract domain from GET parameters
        domain = request.GET.get('domain')

        if not domain:
            return JsonResponse({'status': 0, 'error_message': 'Domain is required.'}, status=400)

        try:
            config = Fail2BanConfig.objects.get(domain=domain)
            return JsonResponse({
                'status': 1,
                'domain': config.domain,
                'max_retries': config.max_retries,
                'find_time': config.find_time,
                'ban_time': config.ban_time,
                'status_codes': config.status_codes,
                'ip_whitelist': config.ip_whitelist
            }, status=200)
        except Fail2BanConfig.DoesNotExist:
            return JsonResponse({'status': 0, 'error_message': f'No configuration found for {domain}'}, status=404)

    except Exception as e:
        return JsonResponse({'status': 0, 'error_message': f'An unexpected error occurred: {str(e)}'}, status=500)

def generate_jail_config(config):
    """
    Generate the jail configuration file content for a domain
    """
    if config.domain == "CyberPanel":
        log_path = '/usr/local/lsws/logs/access.log'
    else:
        log_path = f'/home/{config.domain}/logs/{config.domain}.access_log'
    
    if os.path.exists(ProcessUtilities.debugPath):
        logging.CyberCPLogFileWriter.writeToFile(f"Using log path: {log_path} for {config.domain}")
    
    # Generate ignoreip parameter if whitelist exists
    ignoreip = ""
    whitelist = config.get_whitelist_as_list()
    if whitelist:
        ignoreip = f"\n    ignoreip = 127.0.0.1/8 {' '.join(whitelist)}\n"
    
    return f"""[{config.domain}]
    enabled  = true
    filter   = {config.domain}
    logpath  = {log_path}
    maxretry = {config.max_retries}
    findtime = {config.find_time}
    bantime  = {config.ban_time}
    action   = iptables-allports[name={config.domain}]{ignoreip}
    """

def generate_filter_config(config):
    """
    Generate the filter configuration file content for a domain
    """
    # Create a regex pattern that matches the status codes
    status_codes_pattern = '|'.join(config.status_codes.split(','))

    # Example fail regex: failregex = ^"?<HOST> - - \[.*?\] "(GET|POST|HEAD|PUT|DELETE) .*? HTTP/.*?" (401|403|404|500)
    
    return f"""[Definition]
    failregex = ^"?<HOST> - - \[.*?\] "(GET|POST|HEAD|PUT|DELETE) .*? HTTP/.*?" ({status_codes_pattern})
    ignoreregex =
    """

