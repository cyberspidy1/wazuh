import requests
import json
import pandas as pd
from openpyxl import utils
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, init
import os
from datetime import datetime
import time

init(autoreset=True)

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def authenticate():
    """Authenticate with the Wazuh API and return the token."""
    username = input(Fore.CYAN + "Username: ")
    password = getpass(Fore.CYAN + "Password: ")
    auth_url = "https://localhost:55000/security/user/authenticate?raw=true"
    try:
        response = requests.get(auth_url, auth=(username, password), verify=False)
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException:
        print(Fore.RED + "Authentication failed.")
        return None

def fetch_data_for_agent(agent_id, token):
    """Fetch data for a single agent ID."""
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"https://localhost:55000/syscollector/{agent_id}/packages"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        if response.status_code == 429:  # Too Many Requests
            time.sleep(3)  # Wait for 3 seconds
            response = requests.get(url, headers=headers, verify=False)  # Retry once

        affected_items = response.json().get("data", {}).get("affected_items", [])

        results = []
        for item in affected_items:
            results.append({
                "scan": item.get("scan", {}),
                "architecture": item.get("architecture"),
                "format": item.get("format"),
                "size": item.get("size"),
                "version": item.get("version"),
                "name": item.get("name"),
                "install_time": item.get("install_time"),
                "vendor": item.get("vendor"),
                "agent_id": item.get("agent_id")
            })
        return results

    except requests.RequestException:
        return []

def display_vendor_analytics(df):
    """Display vendor analytics in a tabular format."""
    vendor_counts = df["vendor"].value_counts()
    
    print(Fore.YELLOW + "\nVendor Analytics\n" + "="*50)
    print(Fore.CYAN + "{:<40} | {:<10}".format("Vendor", "Count"))
    print("="*50)
    
    for vendor, count in vendor_counts.items():
        print(Fore.GREEN + "{:<40} | {:<10}".format(vendor, count))

def main():
    print(Fore.YELLOW + "Wazuh API Data Fetcher")
    
    token = authenticate()
    if not token:
        return

    filename = input(Fore.CYAN + "Enter the path to the file containing agent IDs: ")
    with open(filename, 'r') as file:
        agent_ids = [line.strip() for line in file if line.strip()]

    thread_count = int(input(Fore.CYAN + "Enter the thread pool count: "))

    all_data = []

    # Using thread pool to perform requests concurrently.
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(fetch_data_for_agent, agent_id, token): agent_id for agent_id in agent_ids}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing agent IDs", 
                    unit="ID", bar_format='{l_bar}{bar:10}{r_bar}{bar:-10b}', colour='red'):
            
            all_data.extend(future.result())

    # Naming output file based on the current date and time
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"output_{current_time}.xlsx"
    
    # Saving to Excel
    df = pd.DataFrame(all_data)
    df = df.applymap(lambda x: ''.join(ch for ch in str(x) if ch.isprintable()))
    df.to_excel(output_filename, index=False)

    # Displaying the vendor analytics
    display_vendor_analytics(df)

    print(Fore.GREEN + f"\nData written to {output_filename}")

if __name__ == "__main__":
    main()
