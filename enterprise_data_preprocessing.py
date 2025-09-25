import json
import re
import sys
import argparse


def get_filename_from_subcommand(subcommand: str) -> str:
    """Map subcommand to corresponding JSON filename"""
    file_mapping = {
        "enterprise": "enterprise-attack-17.0.1.json",
        "ics": "ics-attack-17.0.1.json",
        "mobile": "mobile-attack-17.0.1.json",
    }

    if subcommand not in file_mapping:
        print(
            f"Error: Unknown subcommand '{subcommand}'. Available options: {list(file_mapping.keys())}"
        )
        sys.exit(1)

    return file_mapping[subcommand]


def extract_mitre_resource(url):
    """Extract MITRE ID from attack.mitre.org URLs"""
    if not url:
        return None
    match = re.search(r"/([TSGM]A?\d{4}(?:\.\d{3})?)", url)
    return match.group(1) if match else None


def extract_mitre_urls(text):
    """Extract MITRE URLs that match techniques or software patterns"""
    if not text:
        return []

    pattern = r"https://attack\.mitre\.org/(?:techniques|software|groups|tactics|campaigns)/[^\s\)]+"
    return re.findall(pattern, text)


def replace_markdown_url_with_resource(text, url, resource):
    """Replace markdown [text](url) with text (resource)"""
    # Escape the URL for regex matching
    escaped_url = re.escape(url)

    # Find [text](url) pattern and replace with text (resource)
    pattern = rf"\[([^\]]+)\]\({escaped_url}\)"
    replacement = rf"\1 ({resource})"

    return re.sub(pattern, replacement, text)


def inspect_relationships(record):
    source_rendered = ""
    source_description_rendered = ""

    target_rendered = ""
    target_description_rendered = ""

    if record["source_ref"].startswith("intrusion-set"):
        source_rendered = intrusion_keys[record["source_ref"]].get("name")
        source_description_rendered = intrusion_keys[record["source_ref"]].get(
            "description"
        )
    elif record["source_ref"].startswith("malware"):
        source_rendered = malware[record["source_ref"]].get("name")
        source_description_rendered = malware[record["source_ref"]].get("description")
    elif record["source_ref"].startswith("x-mitre-data-component"):
        source_rendered = data_component[record["source_ref"]].get("name")
        source_description_rendered = data_component[record["source_ref"]].get(
            "description"
        )
    elif record["source_ref"].startswith("course-of-action"):
        source_rendered = course_of_action[record["source_ref"]].get("name")
        source_description_rendered = course_of_action[record["source_ref"]].get(
            "description"
        )

    if record["target_ref"].startswith("attack-pattern"):
        target_rendered = attack_patterns[record["target_ref"]].get("name")
        target_description_rendered = attack_patterns[record["target_ref"]].get(
            "description"
        )

    source_urls = extract_mitre_urls(source_description_rendered)
    if source_urls:
        for url in source_urls:
            source_description_rendered = replace_markdown_url_with_resource(
                source_description_rendered, url, extract_mitre_resource(url)
            )

    target_urls = extract_mitre_urls(target_description_rendered)
    if target_urls:
        for url in target_urls:
            target_description_rendered = replace_markdown_url_with_resource(
                target_description_rendered, url, extract_mitre_resource(url)
            )

    sample = f"{source_rendered}: {source_description_rendered}\n\n{target_rendered}: {target_description_rendered}\n\n{source_rendered} {record['relationship_type']} {target_rendered}"
    return sample


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Process MITRE ATT&CK framework data")
    parser.add_argument(
        "subcommand",
        choices=["enterprise", "ics", "mobile"],
        help="Choose which ATT&CK framework to process",
    )

    args = parser.parse_args()

    # Get the appropriate filename
    filename = get_filename_from_subcommand(args.subcommand)

    # Initialize your data structures
    metrics = {}
    intrusion_keys = {}
    malware = {}
    data_component = {}
    course_of_action = {}
    attack_patterns = {}

    print(f"Processing {args.subcommand} ATT&CK data from {filename}")
    print("We are starting")

    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        print(
            f"Error: File '{filename}' not found. Please ensure the file exists in the current directory."
        )
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file '{filename}'")
        sys.exit(1)

    objects = data.get("objects")
    samples = []

    for obj in objects:
        if obj["type"] not in metrics.keys():
            metrics[obj["type"]] = 1
        else:
            metrics[obj["type"]] = metrics.get(obj["type"]) + 1

        if obj["type"] == "intrusion-set":
            intrusion_keys[obj["id"]] = obj

        if obj["type"] == "malware":
            malware[obj["id"]] = obj

        if obj["type"] == "x-mitre-data-component":
            data_component[obj["id"]] = obj

        if obj["type"] == "course-of-action":
            course_of_action[obj["id"]] = obj

        if obj["type"] == "attack-pattern":
            attack_patterns[obj["id"]] = obj

        if obj["type"] == "relationship":
            sample = inspect_relationships(
                obj
            )  # Note: you'll need to define this function
            samples.append(sample)
            print(sample)

    json_list = json.dumps(samples)
    print(json_list[:2])  # Print first 2 characters

    print(metrics)


if __name__ == "__main__":
    main()

# metrics = {}
# intrusion_keys = {}
# malware = {}
# data_component = {}
# course_of_action = {}
# attack_patterns = {}

# print("we are starting")
# with open("enterprise-attack-17.1.json", "r") as file:
#    data = json.load(file)

# objects = data.get("objects")
# samples = []

# for obj in objects:
#    if obj["type"] not in metrics.keys():
#        metrics[obj["type"]] = 1
#    else:
#        metrics[obj["type"]] = metrics.get(obj["type"]) + 1

#    if obj["type"] == "intrusion-set":
#        intrusion_keys[obj["id"]] = obj

#    if obj["type"] == "malware":
#        malware[obj["id"]] = obj

#    if obj["type"] == "x-mitre-data-component":
#        data_component[obj["id"]] = obj

#    if obj["type"] == "course-of-action":
#        course_of_action[obj["id"]] = obj

#    if obj["type"] == "attack-pattern":
#        attack_patterns[obj["id"]] = obj

#    if obj["type"] == "relationship":

#        sample = inspect_relationships(obj)
#        samples.append(sample)
#        print(sample)

# json_list = json.dumps(samples)
# print(json_list[2])
# print(len(json_list))


# print(metrics)
