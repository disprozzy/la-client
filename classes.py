from datetime import timedelta, datetime
from subprocess import CalledProcessError, check_output, run
from dotenv import load_dotenv
import os
import requests
import subprocess

class LogParser:
    def __init__(self, 
                 minutes = "30", 
                 path = "", 
                 domain = "*", 
                 log_type = "*access_ssl_log", 
                 code = ""):
        self.path = path
        self.domain = domain
        self.minutes = int(minutes)
        self.log_type = log_type
        self.code = code
        # set time range
        self.end_time = datetime.now()
        self.start_time = self.end_time - timedelta(minutes=self.minutes)

        # set log string to check, all logs by default - nginx and apache
        self.log_string = {
            'main': 'access_ssl_log',
            'proxy': 'proxy_access_ssl_log',
            'all': '*access_ssl_log'
        }.get(self.log_type, '*access_ssl_log')

        # check if custom log path is provided
        if self.path != "":
            self.output = check_output(f"ls -1 {self.path}",
                                  shell=True, universal_newlines=True)
        else:
            self.output = check_output(f"ls -1 /var/www/vhosts/system/{self.domain}/logs/{self.log_string}",
                                  shell=True, universal_newlines=True)

        self.log_files = self.output.strip().split('\n')

    def get_log_time(self,line):
        """ Extract timestamp from the log line in the format [dd/Mon/yyyy:HH:MM:SS +0000] """
        try:
            timestamp_str = line.split("[")[1].split("]")[0].split(" ")[0]
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
        except Exception:
            return None

    def parse_logs(self):
        self.filtered_logs = []
        self.requests_by_domain = {}

        for i, log_file in enumerate(self.log_files, 1):
            # Get domain name from log path
            try:
                domain_name = log_file.split('/system/')[1].split('/')[0]
            except:
                domain_name = "not found"

            self.requests_by_domain.setdefault(domain_name, {'count': 0, 'uniq_ips': set()})

            # Load log file
            with open(log_file, 'r') as f:
                log_lines = f.readlines()

            # Filter log lines in time range
            for line in log_lines:
                log_time = self.get_log_time(line)
                response_code = line.split('"')[2].strip().split()[0]
                if (log_time and self.start_time <= log_time <= self.end_time and
                        (self.code == '' or self.code == response_code)):
                    self.filtered_logs.append(line)
                    self.requests_by_domain[domain_name]['count'] += 1
                    self.requests_by_domain[domain_name]['uniq_ips'].add(line.split()[0])

        # convert the list of uniq IPs to count
        for domain_name in self.requests_by_domain:
            self.requests_by_domain[domain_name]['uniq_ips'] = len(self.requests_by_domain[domain_name]['uniq_ips'])

class Block:
    def __init__(self, api_handler):
        self.filename = '/etc/nginx/conf.d/la.conf'
        self.ips_filename = '/etc/nginx/maps/suspicious_ip.map'
        self.write_mode = 'a' if os.path.exists(self.filename) else 'w'
        self.server_ip = api_handler.server_ip
        self.restart_required = 0

        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                self.existing_lines = set(line.strip() for line in f)
        else:
            with open(self.filename, 'a') as f:
                f.write("#Ban file\n")
            self.existing_lines = set()
            
        if os.path.exists(self.ips_filename):
            with open(self.ips_filename, 'r') as f:
                self.ips_existing_lines = set(line.strip() for line in f)

        self.blocked_ips = api_handler.blocked_ips
        self.whitelisted_ips = api_handler.whitelisted_ips
        self.ddos_mode = api_handler.ddos_mode
        
    def process(self):
        """ 403 rules """
        """
        for ip in self.blocked_ips:
            ip_line = f"deny {ip};"
            if ip_line not in self.existing_lines and ip not in self.whitelisted_ips and ip != self.server_ip:
                with open(self.filename, 'a') as f:
                    f.write(ip_line + "\n")
                restart_required = 1
        """                
                
        for ip in self.blocked_ips:
            ip_line = f"{ip} 1;"
            if ip_line not in self.ips_existing_lines and ip not in self.whitelisted_ips and ip != self.server_ip:
                with open(self.ips_filename, 'a') as f:
                    f.write(ip_line + "\n")
                self.restart_required = 1
                
        # Check if do not have IPs blocked, which are not in DB
        with open(self.ips_filename, 'w') as f:
            default_line = f"default {int(self.ddos_mode)};"
            self.ips_existing_lines.remove(default_line)
            f.write(f"{default_line}\n")
            for ip_line in self.ips_existing_lines:
                if ip_line.split()[0] in self.blocked_ips:
                    f.write(ip_line + "\n")
                else:
                    print(f"{ip_line.split()[0]} should not be blocked. Removing.")
                    self.restart_required = 1            
            
    def set_ddos_mode(self):
        # Check current mode from file contents
        current_mode = "default 1;" in self.ips_existing_lines

        # Only update file if state changed
        if current_mode != self.ddos_mode:

            with open(self.ips_filename, "r+") as f:
                lines = f.readlines()
                lines[0] = f'default {int(self.ddos_mode)};\n'
                f.seek(0)
                f.writelines(lines)
                f.truncate()
            
            print("Applied DDoS mode.")
            self.restart_required = 1
            
    def restart_nginx(self):
        nginx_msg = ''
        if self.restart_required:
            try:
                run(["sudo", "systemctl", "reload", "nginx"], check=True)
                nginx_msg = "Successfully reloaded nginx config to apply the changes."
            except CalledProcessError as e:
                nginx_msg = f"Failed to reload Nginx: {e}"
            print(nginx_msg)            
        

class ApiHandler():
    def __init__(self):
        load_dotenv()
        self.api_url = os.getenv("API_URL", "")
        self.instance_id = os.getenv("INSTANCE_ID", "")
        self.server_ip = get_server_external_ip()
        
    def get_load_stats(self):
        response = requests.get('http://127.0.0.1:80/nginx_status')
        if response.status_code == 200:
            self.total_requests = response.text.strip().splitlines()[2].split()[2]
        
        self.load1, self.load5, self.load15 = os.getloadavg()
    
    def submit_load_stats(self):
        payload = {
            'datatype': 'load_stats',
            'instance_id': self.instance_id,
            'total_requests': self.total_requests,
            'load1': self.load1,
            'load5': self.load5,
            'load15': self.load15,
            'ip': self.server_ip,
        }
        
        response = requests.post(self.api_url, json=payload)
        self.response_data = response.json()
        
        print(self.response_data['message'])
    
    def submit_log_data(self):
        """ Parse logs and submit data using API """
        parser = LogParser(minutes=self.response_data['minutes'])
        parser.parse_logs()
        
        scan_payload = {
            'datatype': 'log_data',
            'instance_id': self.instance_id,
            'filtered_logs': parser.filtered_logs,
            'requests_by_domain': parser.requests_by_domain,
        }
        
        response = requests.post(self.api_url, json=scan_payload)
        log_data_response = response.json()
        
        print(log_data_response['message'])
        
    def process_blocks(self):
        self.blocked_ips = self.response_data.get('blocked_ips', [])
        self.whitelisted_ips = self.response_data.get('whitelisted_ips', [])
        self.ddos_mode = self.response_data['ddos_mode']
        block = Block(self)
        block.process()
        block.set_ddos_mode()
        block.restart_nginx()                   
        
def get_server_external_ip():
    """Get the external IP address of the server from GCP metadata.
        """
    url = "http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
    headers = {"Metadata-Flavor": "Google"}

    response = requests.get(url, headers=headers)
    return response.text

def run_bash_script(url):
    script_path = "/tmp/myscript.sh"
    # Download
    response = requests.get(url)
    response.raise_for_status()  # stop if request failed

    with open(script_path, "wb") as f:
        f.write(response.content)
    
    os.chmod(script_path, 0o755)
    subprocess.run([script_path], check=True)