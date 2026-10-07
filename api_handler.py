from classes import ApiHandler, run_bash_script, ensure_ddosnull_whitelisted, acquire_lock
import subprocess
import os
import sys

# run the updates first to avoid errors; done before taking the lock so a
# stuck run can never keep instances from picking up fixes
try:
    result = subprocess.run(
        ['git', 'pull', 'origin', 'master'],
        cwd='/opt/la-client',
        timeout=120,
    )
except subprocess.TimeoutExpired:
    print("git pull timed out. Continuing with the current version.")

lock_fd = acquire_lock()
if lock_fd is None:
    print("api_handler is already running. Exiting.")
    sys.exit(0)

ensure_ddosnull_whitelisted()

api_handler = ApiHandler()

api_handler.get_load_stats()
api_handler.submit_load_stats()

if api_handler.response_data.get('checkout_protected', False):
    api_handler.check_checkout_requests()

if api_handler.response_data.get('scan_requested', False):
    api_handler.submit_log_data()

api_handler.process_blocks()    