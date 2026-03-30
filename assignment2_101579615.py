"""
Author: GENESIS TUGAWIN
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Import the required modules like socket, threading, sqlite3, os, platform, datetime
import socket
import threading
import sqlite3
import os
import platform
import datetime


# Print Python version and OS name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary that maps common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# NetworkTool parent class
class NetworkTool:
    def __init__(self, target: str):
        self.__target = target


    # Q3: What is the benefit of using @property and @target.setter?
    """
    The @property lets you access target like an attribute while still using a method behind the scenes. 
    The @target.setter lets you control and validate any new value before it is saved, which helps prevent invalid data 
    such as an empty string. Together, they hide the internal implementation and make the class easier and safer to use. 
    They also let you change how target is stored later without breaking code that uses the class.
    """
    @property
    def target(self):
        return self.__target
        
    @target.setter
    def target(self, value: str):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value
            
    def __del__(self):
        print("NetworkTool instance destroyed")



# Q1: How does PortScanner reuse code from NetworkTool?
"""
The PortScanner reuses code from NetworkTool by inheriting from it, so it automatically gets the target property 
and its getter/setter behavior.
In PortScanner.__init__(), super().__init__(target) calls the parent constructor, 
so target setup is done once in `NetworkTool` instead of being duplicated. 
It also calls super().__del__() in its destructor, which reuses parent cleanup behavior and 
shows how child classes can extend, not rewrite, shared functionality.
PortScanner child class that inherits from NetworkTool
"""
class PortScanner(NetworkTool):
    def __init__(self, target: str):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        """
        Without try-except, any socket-related error like DNS resolution failure, connection reset,
        or timeout issues would raise an exception and stop that thread abruptly.
        In a threaded scan, this means some ports may never be recorded in scan_results, giving incomplete
        or misleading output. You would also lose the helpful per-port error message,
        so diagnosing which port failed and why becomes harder. Finally, if an exception occurs
        before normal completion, cleanup becomes less reliable unless finally is still present,
        which can lead to socket or resource handling problems.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
                
            service_name = common_ports.get(port, "Unknown")
            
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]
        
        # Q2: Why do we use threading instead of scanning one port at a time?
        """
        We use threading because port scanning is mostly network I/O, and each connection attempt spends time 
        waiting for a response or timeout. If we scan one port at a time, those waits happen sequentially, 
        making the scan much slower. With threads, many ports are checked at once, so waiting on one port 
        does not block progress on others. This makes scans finish faster and gives results sooner, 
        especially when scanning large port ranges or hosts with many closed or filtered ports.
        """
    def scan_range(self, start_port, end_port):
        threads = []
        # Using end_port + 1 to ensure the final port in the range is scanned
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            
        for t in threads:
            t.start()
            
        for t in threads:
            t.join()

# Save port scan results to SQLite database (save_results function)
def save_results(target, results):

    try:
        # Connect to the database
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        # Insert each result from the results list
        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        # Commit changes and close connection
        conn.commit()
        conn.close()
        print(f"Results saved successfully for {target}")

    except sqlite3.Error as e:
        print(f"Database error: {e}")



# Load and display all past port scan results from the SQLite database (load_past_scans function)
def load_past_scans():
    try:
        # Connect to the database
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        # Execute SELECT to retrieve all rows from scans table
        cursor.execute("SELECT scan_date, target, port, service, status FROM scans ORDER BY scan_date DESC")
        rows = cursor.fetchall()

        # Check if any rows exist
        if not rows:
            print("No past scans found.")
        else:
            print("\n" + "="*70)
            print("PAST SCAN HISTORY")
            print("="*70)
            for row in rows:
                scan_date, target, port, service, status = row
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
            print("="*70 + "\n")

        # Close connection
        conn.close()

    except sqlite3.OperationalError:
        # Handles missing database file or table that does not exist
        print("No past scans found.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")



# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    # Get user input with try-except and target IP default to 127.0.0.1 if empty
    target = input("Enter target IP address (default: 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    # Get start port with validation
    while True:
        try:
            start_port = int(input("Enter starting port (1-1024): "))
            if start_port < 1 or start_port > 1024:
                print("Port must be between 1 and 1024.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Get end port with validation
    while True:
        try:
            end_port = int(input("Enter ending port (1-1024): "))
            if end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
                continue
            if end_port < start_port:
                print("End port must be greater than or equal to start port.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # After valid input,create PortScanner object
    scanner = PortScanner(target)

    # Print scanning message
    print(f"\nScanning {target} from port {start_port} to {end_port}...")

    # Call scan_range()
    scanner.scan_range(start_port, end_port)

    # Get and display open ports
    open_ports = scanner.get_open_ports()
    if open_ports:
        print(f"\n--- Scan Results for {target} ---")
        for port, status, service in open_ports:
            print(f"Port {port}: {status} ({service})")
        print("------")
    else:
        print("\nNo open ports found.")

    # Print total open ports found
    print(f"Total open ports found: {len(open_ports)}\n")


    # Call save_results()
    if open_ports:
        save_results(target, scanner.scan_results)

    # Ask if user wants to see past scan history
    history_choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if history_choice == "yes":
        load_past_scans()


# Q5: New Feature Proposal
"""
I would add a Port Range Presets feature that allows users to select predefined port ranges 
like "Web Services", "Mail Services", or "Database Services" instead of manually typing port numbers. 
When the user selects a preset, the program would scan all commonly associated ports for that category without 
requiring individual port input. This makes scanning faster and more focused for specific security assessments.
The nested if-statements check the user's preset selection and filter common_ports to extract only 
the relevant service ports, eliminating manual port entry for common scenarios.
Diagram: See diagram_101579615.png in the repository root
"""