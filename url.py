import requests

url = "https://www.virustotal.com/api/v3/domains/courseweb.sliit.lk"

headers = {
    "accept": "application/json",
    "x-apikey": "f4e4c770c82857e1132d4f406a8ca29ad34f512e49e544e160461981515fc8fa"
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()

    # Extract and print specific information
    snort_ip_sample_list = data['data']['attributes']['last_analysis_results']['Snort IP sample list']

    # Print a specific category item by key
    specific_category_key = "Forcepoint ThreatSeeker"  # Replace with the desired category key
    specific_category_value = data['data']['attributes']['categories'].get(specific_category_key)

    if specific_category_value is not None:
        # print(f"\n{specific_category_key}: {specific_category_value}")
        print(f"Domain Category : {specific_category_value}")
    else:
        print(f"\nCategory '{specific_category_key}' not found.")

else:
    print("Failed to retrieve data. Status code:", response.status_code)
