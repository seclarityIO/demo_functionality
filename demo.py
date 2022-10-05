"""
    Copyright 2022 SeclarityIO, LLC
    Code created by David Pearson (david@seclarity.io)
    For license information, please see the accompanying LICENSE file in the top-level directory of this repository.
"""

import argparse
import constants
import datetime
import json
import magic
import os
import pathlib
import re
import requests
import sys
import threading
import time
from networksage_tools.converter import convert


def get_filesize(filepath):
    size = os.path.getsize(filepath)
    if size < 1024:
        return f"{size} bytes"
    elif size < 1024*1024:
        return f"{round(size/1024, 2)} KB"
    elif size < 1024*1024*1024:
        return f"{round(size/(1024*1024), 2)} MB"
    elif size < 1024*1024*1024*1024:
        return f"{round(size/(1024*1024*1024), 2)} GB"


def had_error(response):
    """Quick error handling function to avoid code repetition.
    """
    if response.status_code != requests.codes.ok:
        print("Error:", response.text)
        return True
    json_data = json.loads(response.text)
    if json_data["error"]:
        print("Error:", json_data["body"])
        return True
    return False


def get_private_sample_metadata(uuid):
    """Returns high-level information about a private sample (that you own) by
        its UUID. Relevant information returned:
        + dateCreated: time string in format of DD/MM/YYYY HH:MM:SS
        + fileName: string produced by NetworkSage. Will not be the same as the
                    name provided in the front-end.
        + trafficDate: string version of the epoch time (floating-point) that
                    corresponds to when the traffic was actually captured (if your sample is from 2 weeks ago, this will
                    identify that time).
        When the trafficDate value is populated, that means that the sample was successfully processed. Otherwise that
        value will be empty.
    """
    sample_id = uuid

    endpoint_url = constants.SAMPLES_API_ENDPOINT + sample_id
    result = requests.get(endpoint_url, headers=constants.HEADERS)

    if had_error(result):
        return None
    result_json = json.loads(result.text)
    sample_metadata = result_json["body"]
    if len(sample_metadata) == 0:
        sample_metadata = None  # not yet processed
    return sample_metadata



def is_sample_processed(uuid):
    """Wrapper to determine if a sample (whose UUID is passed in) is processed.
    """
    is_processed = False
    sample_metadata = get_private_sample_metadata(uuid)
    if sample_metadata is not None and sample_metadata["trafficDate"] != "":
        is_processed = True
    return is_processed


def wait_for_sample_processing(uuid):
    """Wrapper to poll until sample has been processed. When this returns, the sample will be ready.
    """
    sample_checking_timer = threading.Event()
    while not sample_checking_timer.wait(2.0): # check every 2 seconds
        if is_sample_processed(uuid):
            sample_checking_timer.set()
            break


def wait_for_sample_action(url, action="summary"):
    """Wrapper to poll until sample has been summarized or categorized. When this returns, the sample summary will be
       ready.
    """
    data = None
    action_checking_timer = threading.Event()
    while not action_checking_timer.wait(2.0): # check every 2 seconds
        response = requests.request("GET", url, headers=constants.HEADERS, data={})
        try:
            result = json.loads(response.text)
            if result["body"]["status"] == "generated":
                action_checking_timer.set()
                data = result["body"][action]
                break
        except:
            print(f"Something went wrong while getting sample {action}: {response.text}")
    return data


def summarize_sample(sample_id):
    url = f"{constants.SAMPLES_API_ENDPOINT}{sample_id}{constants.SUMMARY_API_ENDPOINT}"
    response = requests.request("POST", url, headers=constants.HEADERS, data={})
    summary = None
    try:
        result = json.loads(response.text)
        if result["error"]:
            print(f"Something went wrong while requesting sample summary. {response.text}")
            return None
    except:
        print(f"Something went wrong while requesting sample summary. {response.text}")
        return None
    summary = wait_for_sample_action(url, "summary")
    return summary


def upload_sample(converted_file_location, filetype):
    sample_id = None
    sample_name = converted_file_location.name
    payload = {"type": filetype}
    files = [
        ("file",
            (sample_name,
            open(converted_file_location, "rb"),
            "application/octet-stream")
         )
    ]
    response = requests.request("POST",
                                constants.UPLOAD_API_ENDPOINT,
                                headers=constants.HEADERS,
                                data=payload,
                                files=files
                                )
    try:
        result = json.loads(response.text)
        sample_id = result["body"]["sampleId"]
    except:
        print(f"Something went wrong while uploading. Response: {response.text}")
    return sample_id


def get_data_for_existing_sample(action, sampleid):

    data = None
    url = f"{constants.SAMPLES_API_ENDPOINT}{sampleid}/{action}"
    response = requests.request("GET", url, headers=constants.HEADERS, data={})
    try:
        result = json.loads(response.text)
        data = result["body"][action]
    except:
        print(f"Looks like {action} did not exist for {sampleid}. Requesting now.")
        response = requests.request("POST", url, headers=constants.HEADERS, data={})
        data = wait_for_sample_action(url, action=action)
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="demo", usage="%(prog)s [options]")
    parser.add_argument("-a", "--action", help="which action to perform", type=str, choices=["e2e",
                                                                                             "categorization",
                                                                                             "summary"]
                        )
    parser.add_argument("-f", "--file", help="location (relative or absolute) of the file to be processed", type=str)
    parser.add_argument("--dnsfile", help="location (relative or absolute) of an optional DNS log for Zeek", type=str)
    parser.add_argument("-o", "--outputfile", help="name of file to use for storing output", type=str)
    parser.add_argument("--sampleid", help="Sample ID for existing sample", type=str)
    args = parser.parse_args()

    if not args.action:
        print("No action supplied. Quitting!")
        sys.exit(1)
    if not args.file and args.action == "e2e":
        print("No file supplied. Quitting!")
        sys.exit(1)
    output_filename = args.outputfile if args.outputfile else "output.md"
    if args.action in ["categorization", "summary"]:
        if not args.sampleid:
            print(f"Requesting {args.action} requires a valid sample ID. Aborting!")
            sys.exit(1)
        data = get_data_for_existing_sample(args.action, args.sampleid)
        try:
            data_json = json.loads(data)
            with open(output_filename, "w") as out:
                json.dump(data_json, out, indent=4)
        except:
            print(f"Something failed while loading {args.action}. Aborting!")
            sys.exit(1)
        retrieval_end = time.perf_counter()
        print(f"Successfully retrieved {args.action}! Data stored at {output_filename}")
    else:
        original_file_location = pathlib.PurePath(args.file)
        time_prefix = datetime.datetime.now().strftime("%m-%d-%y_T_%H-%M-%S")
        output_directory = pathlib.Path(f"{time_prefix}_{original_file_location.stem}")  # prefix dir with ~ current ts
        detected = None
        start = time.perf_counter()
        print(f"0.0s\tBeginning process")
        file_type = magic.from_file(original_file_location)
        convert_start = time.perf_counter()
        if re.match(r"^(p|)cap(|(|\-)ng) capture file", file_type):
            detected = "PCAP"
        elif re.match(r"^(ASCII text|JSON data)$", file_type):
            detected = "Zeek"
        else:
            print(f"Error: {original_file_location.name}, of type {file_type} is not an accepted file type.")
            sys.exit(1)
        if detected is None: # shouldn't be possible to hit this
            print(f"Error: {original_file_location.name}, of type {file_type} is not an accepted file type.")
            sys.exit(1)
        print(f"{convert_start - start:0.1f}s\tDetected {detected}. Performing local conversion to Secflow format.")
        print(f"\n===================================================")
        output_directory.mkdir()
        if detected == "PCAP":
            convert.convert_pcap(original_file_location, output_dir=output_directory)
            suffix = "_filtered.sf"
        else:  # detected must be "Zeek":
            if args.dnsfile:
                dns_data_location = pathlib.PurePath(args.dnsfile)
                convert.convert_zeek(original_file_location,
                                     zeek_dnsfile_location=dns_data_location,
                                     output_dir=output_directory
                                     )
            else:
                convert.convert_zeek(original_file_location, output_dir=output_directory)
            suffix = ".sf"
        original_file_size = get_filesize(original_file_location)
        converted_file_location = pathlib.PurePath(output_directory, f"{original_file_location.stem}{suffix}")
        converted_file_size = get_filesize(converted_file_location)
        rough_reduction = round(os.path.getsize(original_file_location)/os.path.getsize(converted_file_location))
        convert_end = time.perf_counter()
        print(f"===================================================\n")
        print(f"{convert_end - start:0.1f}s\tConversion complete. Achieved a {rough_reduction}x reduction in size from "
              f"original {detected} file ({original_file_size}) to Secflow file ({converted_file_size})!")
        # now that we've locally converted, upload file to NetworkSage
        upload_start = time.perf_counter()
        print(f"{upload_start - start:0.1f}s\tUploading Secflow to NetworkSage")
        private_sample_id = upload_sample(converted_file_location, filetype="secflow")
        if private_sample_id is None:
            print("Aborting!")
            sys.exit(1)
        upload_complete = time.perf_counter()
        print(f"{upload_complete - start:0.1f}s\tUpload complete! Beginning processing.")
        wait_for_sample_processing(private_sample_id)
        processing_complete = time.perf_counter()
        print(f"{processing_complete - start:0.1f}s\tProcessing complete! Sample can be viewed at "
              f"{constants.UI_SAMPLE_ENDPOINT}{private_sample_id}.")
        start_summary = time.perf_counter()
        print(f"{start_summary - start:0.1f}s\tBeginning sample summarization.")
        summary = summarize_sample(private_sample_id)
        summary_complete = time.perf_counter()
        if summary is None:
            print("Something went wrong while getting summary. Aborting!")
            sys.exit(1)
        try:
            sum_json = json.loads(summary)
            with open(output_filename, "w") as out:
                out.write('\n\n**Verdict:** '+sum_json["verdict"]
                          + '\n**Confidence:** '+sum_json["confidence"]
                          + '\n**Summary:** '+sum_json["summary"]
                          + '\n\n**Details:** '+sum_json["details"]
                          + '\n\n')
        except:
            print(f"Something went wrong while writing output to {output_filename}. Aborting!")
            sys.exit(1)
        print(f"{summary_complete - start:0.1f}s\tSummary complete! Data stored at {output_filename}")

