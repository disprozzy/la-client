from datetime import timedelta, datetime, timezone
from subprocess import CalledProcessError, check_output, run
from dotenv import load_dotenv
import os, sys
import requests
import subprocess

class LogParser:
    def __init__(self, 
                 minutes = "30", 
                 path = "", 
                 domain = "*", 
                 log_type = "*access_ssl_log", 
                 code = ""):
        self.panel = detect_panel()
        self.path = path
        self.domain = domain
        self.minutes = int(minutes)
        self.log_type = log_type
        self.code = code
        # set time range
        self.end_time = datetime.now()
        self.start_time = self.end_time - timedelta(minutes=self.minutes)
        self.checkout_patterns = [
            'POST /?wc-ajax=checkout',
            'GET /random',
            'POST /payment/payment_cc.php'
        ]

        # set log string to check, all logs by default - nginx and apache
        if self.panel == 'plesk':
            self.log_string = {
                'main': 'access_ssl_log',
                'proxy': 'proxy_access_ssl_log',
                'all': '*access_ssl_log'
            }.get(self.log_type, '*access_ssl_log')
            self.full_path = f"/var/www/vhosts/system/{self.domain}/logs/{self.log_string}"
        elif self.panel == 'cpanel':
            self.log_string = '*ssl_log'
            self.full_path = f"/var/log/nginx/domains/{self.domain}{self.log_string}"
        elif self.panel == 'custom_nginx':
            self.log_string = "*_access.log"
            self.full_path = f"/var/log/nginx/{self.domain}{self.log_string}"
        else:
            print("Could not detect log path.")
            sys.exit()

        # check if custom log path is provided
        if self.path != "":
            self.output = check_output(f"ls -1 {self.path}",
                                  shell=True, universal_newlines=True)
        else:
            self.output = check_output(f"ls -1 {self.full_path}",
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
                if self.panel == 'plesk':
                    domain_name = log_file.split('/system/')[1].split('/')[0]
                elif self.panel == 'cpanel':
                    domain_name = log_file.split('/domains/')[1].split('-')[0]
                elif self.panel == 'custom_nginx':
                    domain_name = log_file.split('/ngxinx/')[1].split('_')[0]
            except:
                domain_name = "not found"

            self.requests_by_domain.setdefault(domain_name, {'count': 0, 'uniq_ips': set()})

            # Load log file
            with open(log_file, 'r') as f:
                log_lines = f.readlines()

            # Filter log lines in time range
            for line in log_lines:
                log_time = self.get_log_time(line)
                try:
                    response_code = line.split('"')[2].strip().split()[0]
                except:
                    response_code = 200
                if (log_time and self.start_time <= log_time <= self.end_time and
                        (self.code == '' or self.code == response_code)):
                    self.filtered_logs.append(line)
                    self.requests_by_domain[domain_name]['count'] += 1
                    self.requests_by_domain[domain_name]['uniq_ips'].add(line.split()[0])

        # convert the list of uniq IPs to count
        for domain_name in self.requests_by_domain:
            self.requests_by_domain[domain_name]['uniq_ips'] = len(self.requests_by_domain[domain_name]['uniq_ips'])
        
            
    def process_checkout_ips(self):
        """ Parse the logs and get a list of IP with number of orders submitted 
            Blacklist the IP if submitted more than order per hour
        """
        self.checkout_logs = []
        self.ips_count = {}
        self.suspicious_checkout_ips = []

        for line in self.filtered_logs:
            for pattern in self.checkout_patterns:
                if pattern in line:
                    self.checkout_logs.append(line)
                    
        for i, line in enumerate(self.checkout_logs, 1):
            elements = line.split()
            ip = elements[0]
            if ip in self.ips_count:
                self.ips_count[ip] += 1
            else:
                self.ips_count[ip] = 1
                
        # we'll replace this to a setting later to adjust how many orders an IP can place before we block it
        for ip in self.ips_count.keys():
            if self.ips_count[ip] > 2:
                self.suspicious_checkout_ips.append(ip)
                
                        
class Block:
    def __init__(self, api_handler):
        self.filename = '/etc/nginx/conf.d/la.conf'
        self.ips_filename = '/etc/nginx/maps/suspicious_ip.map'
        self.ddos_filename = '/etc/nginx/maps/ddos_mode.map'
        self.whitelisted_ips_filename = '/etc/nginx/maps/whitelisted_ips.map'
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
        
        self.ddos_existing_lines = load_file_data(self.ddos_filename)    
        self.ips_existing_lines = load_file_data(self.ips_filename)
        self.whitelisted_ips_lines = load_file_data(self.whitelisted_ips_filename)

        self.blocked_ips = api_handler.blocked_ips
        self.whitelisted_ips = api_handler.whitelisted_ips
        self.ddos_mode = api_handler.ddos_mode
        self.ddos_mode_hosts = api_handler.ddos_mode_hosts
        self.disable_all_blocks = api_handler.disable_all_blocks
        
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
                    self.ips_existing_lines.append(ip_line)
                self.restart_required = 1            
                
        # Check if we do not have IPs blocked, which are not in DB
        # load updates ip lines
        with open(self.ips_filename, 'w') as f:
            default_line = f"default 0;"
            if default_line in self.ips_existing_lines:
                self.ips_existing_lines.remove(default_line)
            f.write(f"{default_line}\n")
            for ip_line in self.ips_existing_lines:
                if ip_line.split()[0] in self.blocked_ips:
                    f.write(ip_line + "\n")
                else:
                    print(f"{ip_line.split()[0]} should not be blocked. Removing.")
                    self.restart_required = 1    
                    
        for ip in self.whitelisted_ips:
            ip_line = f"{ip} 1;"
            if ip_line not in self.whitelisted_ips_lines:
                with open(self.whitelisted_ips_filename, 'a') as f:
                    f.write(ip_line + "\n")
                    self.whitelisted_ips_lines.append(ip_line)
                self.restart_required = 1
                
        with open(self.whitelisted_ips_filename, 'w') as f:
            default_line = "default 1;" if self.disable_all_blocks else "default 0;"
            if default_line in self.whitelisted_ips_lines:
                self.whitelisted_ips_lines.remove(default_line)
            f.write(f"{default_line}\n")
            for ip_line in self.whitelisted_ips_lines:
                if ip_line.split()[0] in self.whitelisted_ips:
                    f.write(ip_line + "\n")
                else:
                    print(f"{ip_line.split()[0]} should not be whitelisted. Removing.")
                    self.restart_required = 1            
            
    def set_ddos_mode(self):
        # No hosts mode
        if not self.ddos_mode_hosts:
            # Check current mode from file contents
            current_mode = "default 1;" in self.ddos_existing_lines

            # Only update file if state changed
            if current_mode != self.ddos_mode or len(self.ddos_existing_lines) > 1:
                with open(self.ddos_filename, "w") as f:
                    f.write(f"default {int(self.ddos_mode)};\n")
                
                print("Applied DDoS mode for all websites.")
                self.restart_required = 1
        else:
            # We need to update nginx config if:
            # 1. default is 1
            # 2. config file has ddos mode enabled for a domain which should not blocked
            # 3. config file does not have ddos mode enabled for a domain which shoul be blocked
            if (
                "default 0;" not in self.ddos_existing_lines
                or any(existing_domain.split(' ')[0] not in self.ddos_mode_hosts for existing_domain in self.ddos_existing_lines if not existing_domain.startswith(("www", "default")))
                or any(f"{actual_domain} 1;" not in self.ddos_existing_lines for actual_domain in self.ddos_mode_hosts)
                ):
                                
                with open(self.ddos_filename, "w") as f:
                    f.write(f"default 0;\n")
                     
                for domain in self.ddos_mode_hosts:
                        with open(self.ddos_filename, "a") as f:
                            f.write(f"{domain} 1;\n")
                            f.write(f"www.{domain} 1;\n")
                        print(f"Applied DDoS mode for {domain}.") 
                        self.restart_required = 1
                            
                
            
            
    def restart_nginx(self):
        nginx_msg = ''
        if self.restart_required:
            try:
                run(["sudo", "systemctl", "reload", "nginx"], check=True)
                nginx_msg = "Got updates for the block lists. Successfully reloaded nginx config to apply the changes."
            except CalledProcessError as e:
                nginx_msg = f"Failed to reload Nginx: {e}"
            print(nginx_msg)            
        

class ApiHandler():
    def __init__(self):
        load_dotenv()
        self.api_url = os.getenv("API_URL", "")
        self.instance_id = os.getenv("INSTANCE_ID", "")
        self.server_ip = get_server_external_ip()
    
    def check_checkout_requests(self):
        ddos_mode = self.response_data['ddos_mode']
        if not ddos_mode:
            parser = LogParser(minutes=60)
            parser.parse_logs()
            parser.process_checkout_ips()
            self.suspicious_checkout_ips = parser.suspicious_checkout_ips
            
            if self.suspicious_checkout_ips:
                payload = {
                    'datatype': 'suspicious_checkout_ips',
                    'instance_id': self.instance_id,
                    'suspicious_checkout_ips': self.suspicious_checkout_ips,
                }
                
                response = requests.post(self.api_url, json=payload)
                self.susp_response_data = response.json()
                
                print(self.susp_response_data['message'])
        
        """ Auto ddos mode
            Enable if too many ips are submitting request to checkout
            """
        auto_ddos_enabled_at = datetime.fromisoformat(self.response_data['auto_ddos_enabled_at'].replace("Z", "+00:00")) if self.response_data['auto_ddos_enabled_at'] else None
        checkout_requests = self.response_data['checkout_requests']
        
        if not auto_ddos_enabled_at:
            parser = LogParser(minutes=10)
            parser.parse_logs()
            parser.process_checkout_ips()
            
            if (
                len(parser.checkout_logs) > checkout_requests 
                and len(parser.ips_count) > 1
            ):
                auto_ddos_payload = {
                    'datatype': 'auto_ddos_mode',
                    'instance_id': self.instance_id,
                    'auto_ddos_mode': True,
                    }
                
                response = requests.post(self.api_url, json=auto_ddos_payload)
                self.response_data = response.json()
                
                print(self.response_data['message'])
            
                            
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
        
        ts = self.response_data.get('auto_ddos_enabled_at')
        if ts:
            ts = ts.replace("Z", "+00:00")
            if ts[-3] == ":":
                ts = ts[:-3] + ts[-2:]  # remove colon in timezone for Python 3.6
            self.auto_ddos_enabled_at = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
        else:
            self.auto_ddos_enabled_at = None
        self.auto_ddos_timeout = self.response_data['auto_ddos_timeout'] if self.response_data['auto_ddos_timeout'] else None
        self.now_utc = datetime.now(timezone.utc)
        
        # Check ddos mode evey time load stats are submitted and disable if expired
        if self.auto_ddos_enabled_at and self.auto_ddos_timeout and self.auto_ddos_enabled_at + timedelta(minutes=self.auto_ddos_timeout) < self.now_utc:
            auto_ddos_payload = {
                'datatype': 'auto_ddos_mode',
                'instance_id': self.instance_id,
                'auto_ddos_mode': False,
                }
            
            response = requests.post(self.api_url, json=auto_ddos_payload)
            # Do not overwrite load_stats response data
            response_data = response.json()
            
            print(response_data['message'])
    
    def submit_log_data(self):
        """ Parse logs and submit data using API """
        parser = LogParser(minutes=self.response_data['minutes'])
        parser.parse_logs()
        
        scan_payload = {
            'datatype': 'log_data',
            'instance_id': self.instance_id,
            'filtered_logs': parser.filtered_logs,
            'requests_by_domain': parser.requests_by_domain
        }
        
        response = requests.post(self.api_url, json=scan_payload)
        log_data_response = response.json()
        
        print(log_data_response['message'])    
        
    def process_blocks(self):
        self.blocked_ips = self.response_data.get('blocked_ips', [])
        self.whitelisted_ips = self.response_data.get('whitelisted_ips', []) + [self.server_ip]
        self.ddos_mode = self.response_data['ddos_mode']
        self.ddos_mode_hosts = self.response_data['ddos_mode_hosts']
        self.disable_all_blocks = self.response_data['disable_all_blocks']
        block = Block(self)
        block.process()
        block.set_ddos_mode()
        block.restart_nginx()                            
        
def get_server_external_ip():
    """Get the external IP address of the server from GCP metadata.
        """
    url = "http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
    furl = 'https://finestshops.com/ip.php'
    headers = {"Metadata-Flavor": "Google"}

    try:
        response = requests.get(url, headers=headers)
    except Exception:
        response = requests.get(furl, headers=headers)
        
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
    
def load_file_data(filename):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return list(line.strip() for line in f)
        else:
            return []
        
def detect_panel():
    """Detect whether the server is running Plesk or cPanel"""
    if os.path.isfile("/usr/local/psa/version"):
        return "plesk"
    elif os.path.isfile("/usr/local/cpanel/version"):
        return "cpanel"
    elif os.path.isdir("/etc/nginx/sites-enabled/"):
        return "custom_nginx"
    return None