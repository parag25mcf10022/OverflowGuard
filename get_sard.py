import urllib.request
import json
import zipfile
import os

for tc_id, ver in [("501043", "1.0.0"), ("501317", "1.0.1")]:
    url = f"https://samate.nist.gov/SARD/api/test-cases/{tc_id}/versions/{ver}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            print(f"{tc_id}: {data}")
    except Exception as e:
        print(f"Error fetching {url}: {e}")
