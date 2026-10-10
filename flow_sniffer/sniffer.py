import os
import time
import requests
import subprocess
import threading

BLUE_AGENT_URL = os.environ.get("BLUE_AGENT_URL", "http://blue_agent:8000/api/netflow")

def tail_csv():
    # Wait for cicflowmeter to create the file
    while not os.path.exists("flows.csv"):
        time.sleep(1)
        
    print("Found flows.csv, starting to tail...")
    with open("flows.csv", "r") as f:
        # Read header
        header = f.readline().strip().split(",")
        if not header or header[0] == "":
            header = ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "timestamp"] # Fallback
            
        while True:
            line = f.readline()
            if line:
                values = line.strip().split(",")
                if len(values) == len(header):
                    flow_data = dict(zip(header, values))
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            requests.post(BLUE_AGENT_URL, json=flow_data, timeout=2)
                            print(f"Sent flow to blue_agent: {flow_data.get('Dst Port')}")
                            break
                        except Exception as e:
                            print(f"Failed to send to blue agent (attempt {attempt+1}/{max_retries}): {e}")
                            time.sleep(1)
            else:
                time.sleep(1)

def main():
    print("Starting CICFlowMeter Sniffer...")
    # Run cicflowmeter as a subprocess sniffing on eth0
    # It will append flows to flows.csv as they finish or timeout
    process = subprocess.Popen(["cicflowmeter", "-i", "eth0", "-c", "flows.csv"])
    
    # Start tailing thread
    t = threading.Thread(target=tail_csv)
    t.daemon = True
    t.start()
    
    process.wait()

if __name__ == "__main__":
    main()
