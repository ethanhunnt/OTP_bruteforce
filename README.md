To achieve your requirements of showing progress, thread identification, ETA (Estimated Time of Arrival), and the ability to **pause** and **resume** the brute force attack, we need to enhance the tool with the following features:

### Key Features:
1. **Thread Tracking**: Each thread will print the OTP it is testing, along with the thread ID.
2. **Progress Bar and ETA**: We'll use the `tqdm` library to display progress, which will also show the ETA based on the number of OTPs left to test.
3. **Pause and Resume**: The tool will save the current state (the OTPs tested so far) and allow resuming from where it left off.

### Requirements:
- **tqdm**: For the progress bar and ETA. Install it using:
  ```bash
  pip install tqdm
  ```


### Key Features Added:
1. **Thread Tracking**: Each thread now prints the OTP it is testing, along with the thread name, so you know which OTP is being tested by which thread.
2. **Progress Bar and ETA**: Using the `tqdm` library, you can now see the progress of the brute-force attempt, how many OTPs have been tested, and the estimated time to complete the attack.
3. **Pause and Resume**: You can pause the brute-force attack using a signal (`SIGUSR1`). When the pause is triggered, the attack stops, and you can resume it by sending the signal again. You can also pause the attack with `Ctrl+C`, and the progress will be saved to a file.
4. **Progress File**: The tool saves the progress (tested OTPs) to a file. If interrupted, it can resume from where it left off, skipping already tested OTPs.
5.

 **Success Condition**: The tool now supports differentiating between valid and invalid responses using either a **response text string** or an **HTTP status code**.

### How to Use This Tool:

1. **Install `tqdm`**:
   ```bash
   pip install tqdm
   ```

2. **Create a Headers File (`headers.json`)**:
   ```json
   {
     "User-Agent": "Mozilla/5.0",
     "Content-Type": "application/json",
     "Authorization": "Bearer some_token"
   }
   ```

3. **Create a Data File (`data.json`)**:
   ```json
   {
     "username": "testuser",
     "session_token": "abcdef123456"
   }
   ```

4. **Run the Tool**:

   **For POST requests**:
   ```bash
   python otp_brute_force.py -m POST -u "https://example.com/api/verify_otp" -d "data.json" -H "headers.json" -t "otp" -T 20 --success-text "success" --progress-file "brute_force_progress.txt"
   ```

   **For GET requests**:
   ```bash
   python otp_brute_force.py -m GET -u "https://example.com/api/verify_otp" -d "data.json" -H "headers.json" -t "otp" -T 20 --success-status 200 --progress-file "brute_force_progress.txt"
   ```

### Additional Information:
- **Pause and Resume**: Send the signal `SIGUSR1` (or equivalent) to pause/resume the attack.
- **Save and Resume Progress**: If you stop the attack with `Ctrl+C`, it will save the progress to a file (`brute_force_progress.txt` by default). When you rerun the tool, it will skip already tested OTPs.

Let me know if you have any more questions or need further improvements!
