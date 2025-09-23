import json


def inspect_relationships(record):
    source_rendered = ""
    if record["source_ref"].startswith("intrusion-set"):
        source_rendered = intrusion_keys[record["source_ref"]].get("name")

    print(
        f"{record["type"]}: {record["source_ref"]} {record["relationship_type"]} {record["target_ref"]}."
    )
    print(f"source_rendered: {source_rendered}")


metrics = {}
intrusion_keys = {}

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

    if obj["type"] == "relationship":
        inspect_relationships(obj)
