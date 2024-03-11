import os
import requests

# your api key here
API_KEY = "your_api_key"

def search_samples(search_rule, limit):
    """
    get hashes by given rule
    :param search_rule: string - the given rule
    :param limit: int - hash list length limit
    """
    url = "https://www.virustotal.com/api/v3/intelligence/search"
    headers = {
        "x-apikey": API_KEY
    }
    all_hashes = []
    max_limit = 300
    next_cursor = ""

    while limit > 0:
        params = {
            "query": search_rule,
            "limit": min(limit, max_limit),
        }
        if next_cursor:
            params["cursor"] = next_cursor

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            json_response = response.json()
            samples = json_response["data"]
            hashes = [sample["id"] for sample in samples]
            #print(hashes)
            all_hashes.extend(hashes)
            limit -= max_limit

            if "cursor" in json_response["meta"]:
                next_cursor = json_response["meta"]["cursor"]
            else:
                break
        else:
            print(response.content)
            print(f"Error: Unable to search samples. Status code: {response.status_code}")
            return []

    return all_hashes

def download_samples(hashes, path):
    """
    download samples to the given file path
    :param hashes: list[string] - the given hash list
    :param path: string - the target downloaded file path, excluding the file name
    """
    for file_hash in hashes:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/download"
        headers = {
            "x-apikey": API_KEY
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            file_path = os.path.join(path, f"{file_hash}.bin")
            with open(file_path, "wb") as f:
                f.write(response.content)
            print(f"Sample saved as {file_path}")
        else:
            print(f"Error: Unable to download sample {file_hash}. Status code: {response.status_code}")

if __name__ == "__main__":
    search_rule = "engines:backdoor and type:elf AND size:5000000- and AND positives:20+"
    limit = 20
    hashes = search_samples(search_rule, limit)
    download_path = ".\\backdoor"
    download_samples(hashes, download_path)
