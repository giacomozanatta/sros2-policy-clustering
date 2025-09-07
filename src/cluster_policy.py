import os
import argparse
import logging
from .permissions import parse_policy_file
from .clustering import (
    hierarchical_clustering,
    compute_jaccard_distance_matrix,
    permissions_to_bitvector,
    build_global_permission_set,
)
from .report import generate_cluster_report, generate_clustered_policy_xml

def main(policy_dir, output_dir, threshold):
    logging.info(f"Parsing policy files from {policy_dir}")
    profiles_permissions = {}

    for filename in os.listdir(policy_dir):
        if not filename.endswith(".xml"):
            continue
        filepath = os.path.join(policy_dir, filename)
        parsed = parse_policy_file(filepath)
        for node, perms in parsed.items():
            if node in profiles_permissions:
                profiles_permissions[node].update(perms)
            else:
                profiles_permissions[node] = perms

    global_permissions = build_global_permission_set(profiles_permissions)
    nodes = sorted(profiles_permissions.keys())
    bitvectors = [permissions_to_bitvector(profiles_permissions[node], global_permissions) for node in nodes]

    logging.info("Computing Jaccard distance matrix")
    dist_matrix = compute_jaccard_distance_matrix(bitvectors)

    logging.info(f"Performing hierarchical clustering with threshold {threshold}")
    clusters = hierarchical_clustering(dist_matrix, threshold)

    clusters_dict = {}
    for node, cluster_id in zip(nodes, clusters):
        clusters_dict.setdefault(cluster_id, []).append(node)

    logging.info("Generating clustering report")
    report = generate_cluster_report(dist_matrix, clusters, nodes, profiles_permissions, clusters_dict)

    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "clustering_report.txt")
    with open(report_path, "w") as f:
        f.write(report)
    logging.info(f"Clustering report saved to {report_path}")

    logging.info("Generating clustered policy XML")
    clustered_policy_xml, _ = generate_clustered_policy_xml(nodes, clusters, profiles_permissions)

    policy_path = os.path.join(output_dir, "clustered_policy.xml")
    with open(policy_path, "w") as f:
        f.write(clustered_policy_xml)
    logging.info(f"Clustered policy XML saved to {policy_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SROS2 Policy Clustering Tool")
    parser.add_argument("--policy_dir", type=str, default="./policies", help="Directory with XML policy files")
    parser.add_argument("--output_dir", type=str, default="./output", help="Directory to save reports and clustered policies")
    parser.add_argument("--threshold", type=float, default=0.8, help="Clustering similarity threshold (0.0-1.0)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    main(args.policy_dir, args.output_dir, args.threshold)