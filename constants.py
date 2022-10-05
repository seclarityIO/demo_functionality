"""
    Copyright 2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)
    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import os

API_KEY = os.environ.get("NETWORKSAGE_DEMO_API_KEY")
API_ENDPOINT = "https://api.seclarity.io/"
UPLOAD_API_ENDPOINT = f"{API_ENDPOINT}upload/v1.0/uploader"
SECFLOWS_API_ENDPOINT = f"{API_ENDPOINT}public/v1.0/secflows/"
DESTINATION_API_ENDPOINT = f"{API_ENDPOINT}sec/v1.0/destinations/"
SAMPLES_API_ENDPOINT = f"{API_ENDPOINT}sec/v1.0/samples/"
CATEGORIZATION_API_ENDPOINT = f"/categorization"
SUMMARY_API_ENDPOINT = f"/summary"
HEADERS = {"apikey": API_KEY}
UI_SAMPLE_ENDPOINT = "https://networksage.seclarity.io/samples/"

