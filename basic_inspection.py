import json
import re


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

    pattern = r"https://attack\.mitre\.org/(?:techniques|software)/[^\s\)]+"
    return re.findall(pattern, text)


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

    source_urls = extract_mitre_urls(
        data_component[record["source_ref"]].get("description")
    )

    print(f"urls collected from source {source_urls}")

    print("-----------------")
    print(f"{source_rendered}: {source_description_rendered}")
    print("#################")
    print()
    print()
    print(f"{target_rendered}: {target_description_rendered}")
    print("#################")
    print()
    print()
    print(f"{source_rendered} {record['relationship_type']} {target_rendered}")
    print(record)
    print("-----*********")


metrics = {}
intrusion_keys = {}
malware = {}
data_component = {}
course_of_action = {}
attack_patterns = {}

print("we are starting")
with open("enterprise-attack-17.1.json", "r") as file:
    data = json.load(file)

objects = data.get("objects")

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
        inspect_relationships(obj)

print(metrics)
