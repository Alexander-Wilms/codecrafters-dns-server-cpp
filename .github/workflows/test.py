import subprocess
import re

output = subprocess.check_output("build/server > /dev/null & sleep 5 && dig @127.0.0.1 -p 2053 +noedns google.com", shell=True, universal_newlines=True)

pattern = r"google\.com.*8\.8\.8\.8"

match = re.search(pattern, output)

if not match:
    print(f"pattern '{pattern}' not found in dig output")
    exit(1)

if "Warning" in output:
    print(f"dig output contains warning")
    exit(1)

print("no problems detected")