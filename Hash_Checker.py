import os
import hashlib
import colorama
import pyfiglet
from colorama import Fore, Style
import requests

colorama.init(autoreset=True)

API_KEY = input("Please Enter VirusTotal APIKEY: ")
ALIENVAULT_API_KEY = input("Please Enter AlienVault APIKEY: ")

def list_files(source_directory):
    try:
        for root, dirs, files in os.walk(source_directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                hash_value = calculate_files_hash(file_path)
                print(f"{Fore.BLUE}File found:{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{file_path}{Style.RESET_ALL} {Fore.BLUE}and its hash is -{Style.RESET_ALL} {Fore.LIGHTCYAN_EX}{hash_value}{Style.RESET_ALL}")
        check_files_hash_and_scan(source_directory)
    except FileNotFoundError:
        print(f"Directory '{source_directory}' not found.")
    except PermissionError:
        print(f"Permission denied for '{source_directory}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

def calculate_files_hash(file_path, chunk_size=65536):
    try:
        with open(file_path, 'rb') as f:
            hasher = hashlib.sha256()
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                hasher.update(data)
            return hasher.hexdigest()
    except Exception as e:
        print(f"Couldn't calculate hash for '{file_path}': {e}")


def check_files_hash_and_scan(source_directory):
    print(f"{Fore.LIGHTGREEN_EX}=== VirusTotal Scan ==={Style.RESET_ALL}")
    try:
        for root, dirs, files in os.walk(source_directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                hash_value = calculate_files_hash(file_path)
                vt_result = scan_on_virustotal(hash_value, file_path)

                if vt_result['found']:
                    if vt_result['malicious']:
                        print(
                            f"{Fore.RED}Malicious Attachment Detected on VirusTotal:{Style.RESET_ALL} {file_name}, {hash_value}")
                    elif 'clean' in vt_result and vt_result['clean']:
                        print(f"{Fore.GREEN}Clean Attachment Detected on VirusTotal:{Style.RESET_ALL} {file_name}, {hash_value}")
                    else:
                        print(f"{Fore.YELLOW}Attachment found on VirusTotal but no verdict available:{Style.RESET_ALL} {file_name},{hash_value}")
                else:
                    print(f"{Fore.YELLOW}Attachment not found on VirusTotal:{Style.RESET_ALL} {file_name},{hash_value}")

    except FileNotFoundError:
        print(f"Directory '{source_directory}' not found.")
    except PermissionError:
        print(f"Permission denied for '{source_directory}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

    print(f"\n{Fore.LIGHTGREEN_EX}=== AlienVault Scan ==={Style.RESET_ALL}")
    try:
        for root, dirs, files in os.walk(source_directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                hash_value = calculate_files_hash(file_path)
                av_result = scan_on_alienvault(hash_value, file_path)

                if av_result['found']:
                    if av_result['malicious']:
                        print(
                            f"{Fore.RED}Malicious Attachment Detected on AlienVault:{Style.RESET_ALL} {file_name}, {hash_value}")
                    elif 'clean' in av_result and av_result['clean']:
                        print(f"{Fore.GREEN}Clean Attachment Detected on AlienVault:{Style.RESET_ALL} {file_name}, {hash_value}")
                    else:
                        print(f"{Fore.YELLOW}Attachment found on AlienVault but no verdict available:{Style.RESET_ALL} {file_name},{hash_value}")
                else:
                    print(f"{Fore.YELLOW}Attachment not found on AlienVault:{Style.RESET_ALL} {file_name},{hash_value}")

                print()
    except FileNotFoundError:
        print(f"Directory '{source_directory}' not found.")
    except PermissionError:
        print(f"Permission denied for '{source_directory}'.")
    except Exception as e:
        print(f"An error occurred: {e}")


def scan_on_virustotal(hash, file_path):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash}"
        headers = {"x-apikey": API_KEY}
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad responses
        data = response.json()
        if 'data' in data:
            attributes = data['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious = stats['malicious']
                return {'found': True, 'malicious': malicious}
    except requests.exceptions.RequestException as e:
        print(f"Error scanning file '{file_path}'")
    except Exception as e:
        print(f"An error occurred while scanning file '{file_path}': {e}")
    return {'found': False}

def scan_on_alienvault(hash, file_path):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash}/analysis"
        headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad responses
        data = response.json()
        if data.get('result', '') == 'malicious':
            return {'found': True, 'malicious': True}
        elif data.get('result', '') == 'clean':
            return {'found': True, 'clean': True}
    except requests.exceptions.RequestException as e:
        print(f"Error scanning file '{file_path}'")
    except Exception as e:
        print(f"An error occurred while scanning file '{file_path}': {e}")
    return {'found': False}

if __name__ == "__main__":
    welcome_message = "Hash_Checker"
    ASCII_art_1 = pyfiglet.figlet_format(welcome_message)
    print(ASCII_art_1)
    source_directory = input("Please choose a directory: ")
    list_files(source_directory)
