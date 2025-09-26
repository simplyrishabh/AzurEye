import os

def write_findings(module_name, subscription, resource_name, findings):
    output_dir = f"results/{module_name}/{subscription}"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{resource_name}.txt")
    with open(file_path, "w") as f:
        f.write(findings)
