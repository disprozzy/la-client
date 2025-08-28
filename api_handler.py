from classes import ApiHandler, run_bash_script
import subprocess
import os
import re

# run the updates first to avoid errors
result = subprocess.run(
    ['git', 'pull', 'origin', 'master'],
    cwd='/opt/la-client',
)

# add nginx configs
filename = '/etc/nginx/conf.d/ddosnull.conf'
if not os.path.exists(filename):
    run_bash_script('https://finestshops.com/conf/updater.3.1.sh')
    
# switch geo
# Read original file
with open(filename, "r") as f:
    content = f.read()

# Replace map $remote_addr ... { with geo $remote_addr ... {
updated_content = re.sub(
    r'\bmap\s+(\$remote_addr)\s+(\$is_suspicious_ip)\s*\{',
    r'geo \1 \2 {',
    content
)

# Write back to file
with open(filename, "w") as f:
    f.write(updated_content)
    

api_handler = ApiHandler()

api_handler.get_load_stats()
api_handler.submit_load_stats()

if api_handler.response_data.get('checkout_protected', False):
    api_handler.check_checkout_requests()

if api_handler.response_data.get('scan_requested', False):
    api_handler.submit_log_data()

api_handler.process_blocks()    