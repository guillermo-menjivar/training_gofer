import json

metrics = {}

with open("enterprise-attack-17.1.json", "r") as file:
    data = json.load(file)

objects = data.get("objects")

for obj in objects:
    if obj["type"] not in metrics.keys():
        metrics[obj["type"]] = 1
    else:
        metrics[obj["type"]] = metrics.get(obj["type"]) + 1

print(metrics)
