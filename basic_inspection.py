import json


def inspect_relationships(record):
    print(
        f"{record["type"]}: {record["source_ref"]} {record["relationship_type"]} {record["target_ref"]}."
    )


metrics = {}

with open("enterprise-attack-17.1.json", "r") as file:
    data = json.load(file)

objects = data.get("objects")

for obj in objects:
    if obj["type"] not in metrics.keys():
        metrics[obj["type"]] = 1
    else:
        metrics[obj["type"]] = metrics.get(obj["type"]) + 1

    if obj["type"] == "relationship":
        inspect_relationships(obj)
print(metrics)
