import json


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
        print(record)
        print(attack_patterns.keys())
        target_rendered = attack_patterns[record["target_ref"]]
        # target_rendered = attack_patterns[record["target_ref"]].get("name")
        # target_description_rendered = attack_patterns[record["target_ref"]].get(
        #    "description"
        # )

    print("-----------------")
    print(
        f"{record["type"]}: {record["source_ref"]} {record["relationship_type"]} {record["target_ref"]}."
    )
    print("-----------------")
    print(
        f"{source_rendered}: {source_description_rendered} {record['relationship_type']} {target_rendered}"
    )


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
