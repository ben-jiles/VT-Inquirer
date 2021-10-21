#import
import getpass
import sys
import json
import subprocess
import os
import requests

#welcome
print("Welcome, "+getpass.getuser()+"." + "\n")

#key management
userkey = raw_input("Please insert VirusTotal API token: ")

#main menu
def main():
    #run main menu
    print_menu()

def print_menu():
    print "\n", 30 * "-" , "MAIN MENU" , 30 * "-"
    choice = input("""
       
        1. Scan URL
        2. Scan domain
        3. Scan IP
        4. Exit
        
        Please enter choice [1-4]:""")
    if choice == "1":
        scanurl()
    elif choice == "2":
        scandomain()
    elif choice == 3:
        scanip()
    elif choice == "4":
        sys.exit
    else:
        print "Please try again."
        print_menu()

def scanurl():
    url = input("Please enter url:")
    jsonparser(vt.geturl(url))

def scandomain():
    domain = input("Please enter domain:")
    jsonparser(vt.getdomain(domain))

def scanip():
    print "\n", 30 * "-" , "SCAN IP ADDRESSES" , 30 * "-"
    choice_ip = raw_input("""
    
        Would you like to:
        1. Scan single IP?
        2. Upload txt of multiple IPs?

        Please enter your choice [1-2]:""")
        
    if choice_ip == "1":
        ip = raw_input("Please enter IP:")
        url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip
        headers = {'x-apikey':userkey}
        response = requests.get(url, headers=headers)
        print response
        storage = response.json()
        print storage
        vt_ip_score_malicious = str(storage['data']['attributes']['last_analysis_stats']['malicious'])
        vt_ip_score_harmless = str(storage['data']['attributes']['last_analysis_stats']['harmless'])
        vt_ip_score_full = vt_ip_score_malicious + "/" + vt_ip_score_harmless
        vt_ip_url = 'https://www.virustotal.com/gui/ip-address/' + ip
        vt_ip_full_entry = vt_ip_score_full + ", " + vt_ip_url + "\n"
        print(vt_ip_full_entry)
    
    elif choice_ip == "2":
        file_upload_name = raw_input("\nPlease enter full file path to submit: ")
        file_output_name = raw_input("\nPlease enter filename for scan results output: ")
        file_output = open(file_output_name, 'a')
        with open(file_upload_name, 'r') as file_upload:
            for raw_ip in file_upload:
                ip = raw_ip.strip()
                url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip
                headers = {'x-apikey':userkey}
                response = requests.get(url, headers=headers)
                print response
                storage = response.json()
                print storage
                vt_ip_score_malicious = str(storage['data']['attributes']['last_analysis_stats']['malicious'])
                vt_ip_score_harmless = str(storage['data']['attributes']['last_analysis_stats']['harmless'])
                vt_ip_country = str(storage['data']['attributes']['country'])
                vt_ip_score_full = vt_ip_score_malicious + "/" + vt_ip_score_harmless
                vt_ip_url = 'https://www.virustotal.com/gui/ip-address/' + ip
                vt_ip_full_entry = vt_ip_score_full + ", " + vt_ip_url + ", " + vt_ip_country + "\n"
                print(vt_ip_full_entry)
                file_output.write(vt_ip_full_entry)

        file_output.close()
        print "VirusTotal IP address scans are complete and are now available in your ouput file.\n"
    
    else:
        print "Please try again."
        scanip()

    ip_last_choice = raw_input("""
        
        That completes your IP scan(s). Do you wish to scan more IPs or other objects?

        1. More IPs plz!
        2. Yeah I gotta scan domains, URLs, files, etc.
        3. Exit

        Please enter your choice:""")
    if ip_last_choice == "1":
        scanip()
    elif ip_last_choice == "2":
        print_menu()
    elif ip_last_choice == "3":
        sys.exit("\nGoodbye, friend.")
    else:
        print "Please try again."

if __name__ == '__main__':
    main()