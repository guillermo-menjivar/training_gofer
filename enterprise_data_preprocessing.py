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

    print("-------NEW ENTRY----------")
    sample = f"{source_rendered}: {source_description_rendered}\n\n{target_rendered}: {target_description_rendered}\n\n{source_rendered} {record['relationship_type']} {target_rendered}"
    print(sample)


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
