import os
import hashlib
import requests
import subprocess

# Function to load file paths from a directory recursively
def get_file_paths(directory):
    file_paths = []
    for root, directories, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_paths.append(file_path)
    return file_paths

# Function to load file paths from the entire drive
def get_all_file_paths(drive):
    return get_file_paths(drive + "\\")

# Function to load file paths from the whitelist file
def load_whitelist(whitelist_file):
    with open(whitelist_file, 'r') as file:
        return [line.strip() for line in file]

# Function to load file paths from the blacklist file
def load_blacklist(blacklist_file):
    with open(blacklist_file, 'r') as file:
        return [line.strip() for line in file]

# Function to compute the md5 hash of a file
def compute_file_hash(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

# Function to check if a file is marked as suspicious by VirusTotal
def is_file_suspicious(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(data)
        if "data" in data and "attributes" in data["data"]:
            attributes = data["data"]["attributes"]
            if "last_analysis_stats" in attributes:
                analysis_stats = attributes["last_analysis_stats"]
                if analysis_stats.get("suspicious", 0) > 0:
                    return True
    return False

# Function to delete a file using Electron (requires Electron installed and configured)
def delete_file(file_path):
    # Replace this with your Electron command to delete the file
    command = f"electron deleteFile.js {file_path}"
    subprocess.run(command, shell=True)

# Function to scan the drive for files and check against the whitelist and blacklist
def scan_drive(drive, whitelist_file, blacklist_file, api_key):
    file_paths = get_all_file_paths(drive)
    whitelist = load_whitelist(whitelist_file)
    blacklist = load_blacklist(blacklist_file)
    scan_results = []

    for file_path in file_paths:
        file_hash_md5 = compute_file_hash(file_path)
        state = ""

        # Check if the file hash is in the blacklist
        with open(blacklist_file, 'r') as file:
            blacklist_lines = file.readlines()
            for line in blacklist_lines:
                if file_hash_md5 == line.strip():
                    # Check if the file hash is also in the whitelist
                    if file_hash_md5 in whitelist:
                        state = f"[INFO] Safe passed by whitelist: {file_path} (MD5: {file_hash_md5})"
                    else:
                        # Check if the file is marked as suspicious by VirusTotal
                        if is_file_suspicious(file_hash_md5, api_key):
                            delete_file(file_path)
                            state = f"[WARNING] Danger marked by virustotal: {file_path} (MD5: {file_hash_md5}) - File deleted."
                        else:
                            state = f"[INFO] Safe marked by virustotal: {file_path} (MD5: {file_hash_md5})"
                    break
            else:
                state = f"[INFO] Safe: {file_path} (MD5: {file_hash_md5})"

        scan_results.append(state)

    return scan_results

def scan_file(file_path, whitelist_file, blacklist_file, api_key):
    whitelist = load_whitelist(whitelist_file)
    blacklist = load_blacklist(blacklist_file)
    file_hash_md5 = compute_file_hash(file_path)
    state = ""

    # Check if the file hash is in the blacklist
    with open(blacklist_file, 'r') as file:
        blacklist_lines = file.readlines()
        for line in blacklist_lines:
            if file_hash_md5 == line.strip():
                # Check if the file hash is also in the whitelist
                if file_hash_md5 in whitelist:
                    state = f"[Local: INFO] Passed by whitelist: {file_path} (MD5: {file_hash_md5})"
                else:
                    # Check if the file is marked as suspicious by VirusTotal
                    if is_file_suspicious(file_hash_md5, api_key):
                        delete_file(file_path)
                        state = f"[Cloud: WARNING] Danger: {file_path} (MD5: {file_hash_md5}) - File deleted."
                    else:
                        state = f"[Cloud: INFO] Safe: {file_path} (MD5: {file_hash_md5})"
                break
        else:
            state = f"[Local: INFO] Safe: {file_path} (MD5: {file_hash_md5})"
    return state

# Function to write scan results to a file
def write_results_to_file(results, output_file):
    with open(output_file, "w") as file:
        for result in results:
            file.write(result + "\n")

def prefect_path(path):
    return os.path.dirname(path) + '\\' + os.path.basename(path)

# Main function
def main():
    option = input("Scan a single file (1) or scan the entire drive (2)? ")
    whitelist_file = prefect_path("src/script/data/whitelist.txt")  # Update with the path to your whitelist file
    blacklist_file = prefect_path("src/script/data/blacklist.txt")  # Update with the path to your blacklist file
    virustotal_api_key = ""  # Update with your VirusTotal API key
    output_file = "scan_results.txt"  # Update with the path to the output file

    if option == "1":
        file_path = input("Enter the file path to scan: ")
        scan_result = scan_file(prefect_path(file_path), whitelist_file, blacklist_file, virustotal_api_key)
        write_results_to_file([scan_result], output_file)
        print("Scan complete. Results written to scan_results.txt.")
    elif option == "2":
        drive = input("Enter the drive to scan (e.g., C:\\): ")
        scan_results = scan_drive(drive, whitelist_file, blacklist_file, virustotal_api_key)
        write_results_to_file(scan_results, output_file)
        print("Scan complete. Results written to scan_results.txt.")
    else:
        print("Invalid option. Please try again.")

# Run the main function
if __name__ == "__main__":
    main()