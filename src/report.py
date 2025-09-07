from lxml import etree
import numpy as np

def build_profile_xml(cluster_permissions, global_permissions):
    profile = etree.Element("profile", ns="/", node="cluster_node")

    topics_pub = set()
    topics_sub = set()
    services = set()
    actions = set()
    param_get = set()
    param_set = set()

    for perm in cluster_permissions:
        if perm.startswith("pub:"):
            topics_pub.add(perm[len("pub:"):])
        elif perm.startswith("sub:"):
            topics_sub.add(perm[len("sub:"):])
        elif perm.startswith("srv:"):
            services.add(perm[len("srv:"):])
        elif perm.startswith("act:"):
            actions.add(perm[len("act:"):])
        elif perm.startswith("param_get:"):
            param_get.add(perm[len("param_get:"):])
        elif perm.startswith("param_set:"):
            param_set.add(perm[len("param_set:"):])

    if topics_pub or topics_sub:
        attr = {}
        if topics_pub:
            attr["publish"] = "ALLOW"
        if topics_sub:
            attr["subscribe"] = "ALLOW"
        topics_elem = etree.SubElement(profile, "topics", **attr)

        all_topics = sorted(topics_pub.union(topics_sub))
        for topic in all_topics:
            topic_elem = etree.SubElement(topics_elem, "topic")
            topic_elem.text = topic

    if services:
        services_elem = etree.SubElement(profile, "services", allow="ALLOW")
        for srv in sorted(services):
            srv_elem = etree.SubElement(services_elem, "service")
            srv_elem.text = srv

    if actions:
        actions_elem = etree.SubElement(profile, "actions", allow="ALLOW")
        for act in sorted(actions):
            act_elem = etree.SubElement(actions_elem, "action")
            act_elem.text = act

    if param_get:
        params_get_elem = etree.SubElement(profile, "parameters", get="ALLOW")
        for p in sorted(param_get):
            p_elem = etree.SubElement(params_get_elem, "parameter")
            p_elem.text = p

    if param_set:
        params_set_elem = etree.SubElement(profile, "parameters", set="ALLOW")
        for p in sorted(param_set):
            p_elem = etree.SubElement(params_set_elem, "parameter")
            p_elem.text = p

    return profile


def generate_clustered_policy_xml(nodes, clusters, profiles_permissions):
    clusters_dict = {}
    for node, cluster_id in zip(nodes, clusters):
        clusters_dict.setdefault(cluster_id, []).append(node)

    policy_root = etree.Element("policy", version="0.2.0", nsmap={'xi': 'http://www.w3.org/2001/XInclude'})
    enclaves_elem = etree.SubElement(policy_root, "enclaves")

    for cid, cluster_nodes in clusters_dict.items():
        enclave_path = f"/cluster_{cid}"
        enclave_elem = etree.SubElement(enclaves_elem, "enclave", path=enclave_path)
        profiles_elem = etree.SubElement(enclave_elem, "profiles")

        merged_permissions = set()
        for node in cluster_nodes:
            merged_permissions.update(profiles_permissions[node])

        profile_elem = build_profile_xml(merged_permissions, set())
        profile_elem.set("node", f"cluster_{cid}_nodes_{len(cluster_nodes)}")
        profiles_elem.append(profile_elem)

    xml_str = etree.tostring(policy_root, pretty_print=True, encoding='UTF-8', xml_declaration=True).decode()

    return xml_str, clusters_dict

def generate_cluster_report(dist_matrix, clusters, nodes, profiles_permissions, clusters_dict):
    num_clusters = len(set(clusters))
    cluster_sizes = [np.sum(clusters == c) for c in set(clusters)]
    avg_cluster_size = np.mean(cluster_sizes)

    intra_dists = []
    for c in set(clusters):
        indexes = np.where(clusters == c)[0]
        if len(indexes) < 2:
            continue
        submatrix = dist_matrix[np.ix_(indexes, indexes)]
        triu_idx = np.triu_indices(len(indexes), k=1)
        if len(triu_idx[0]) == 0:
            continue
        mean_dist = np.mean(submatrix[triu_idx])
        intra_dists.append(mean_dist)

    avg_intra_cluster_distance = np.mean(intra_dists) if intra_dists else 0.0

    # Build cluster-level pub/sub/srv/act sets and also map node-level perms
    cluster_pub = {}
    cluster_sub = {}
    cluster_srv = {}
    cluster_act = {}
    cluster_nodes_perms = {}

    for cid, cluster_nodes in clusters_dict.items():
        cluster_pub[cid] = set()
        cluster_sub[cid] = set()
        cluster_srv[cid] = set()
        cluster_act[cid] = set()
        cluster_nodes_perms[cid] = {"pub": {}, "sub": {}, "srv": {}, "act": {}}
        for node in cluster_nodes:
            perms = profiles_permissions[node]
            for perm in perms:
                if perm.startswith("pub:"):
                    topic = perm[len("pub:") :]
                    cluster_pub[cid].add(topic)
                    cluster_nodes_perms[cid]["pub"].setdefault(node, set()).add(topic)
                elif perm.startswith("sub:"):
                    topic = perm[len("sub:") :]
                    cluster_sub[cid].add(topic)
                    cluster_nodes_perms[cid]["sub"].setdefault(node, set()).add(topic)
                elif perm.startswith("srv:"):
                    service = perm[len("srv:") :]
                    cluster_srv[cid].add(service)
                    cluster_nodes_perms[cid]["srv"].setdefault(node, set()).add(service)
                elif perm.startswith("act:"):
                    action = perm[len("act:") :]
                    cluster_act[cid].add(action)
                    cluster_nodes_perms[cid]["act"].setdefault(node, set()).add(action)

    communication_flows = []

    cluster_ids = sorted(clusters_dict.keys())
    for i in cluster_ids:
        for j in cluster_ids:
            if i == j:
                continue
            topics_flow = cluster_pub[i].intersection(cluster_sub[j])
            srv_flow = cluster_srv[i].intersection(cluster_srv[j])
            act_flow = cluster_act[i].intersection(cluster_act[j])

            if topics_flow or srv_flow or act_flow:
                communication_flows.append(
                    {
                        "from": i,
                        "to": j,
                        "topics": sorted(topics_flow),
                        "services": sorted(srv_flow),
                        "actions": sorted(act_flow),
                    }
                )

    enclave_exposers = {}
    enclave_subscribers = {}

    for cid in cluster_ids:
        external_pub_perms = set()
        for other_cid in cluster_ids:
            if other_cid == cid:
                continue
            external_pub_perms.update(cluster_pub[cid].intersection(cluster_sub[other_cid]))

        external_sub_perms = set()
        for other_cid in cluster_ids:
            if other_cid == cid:
                continue
            external_sub_perms.update(cluster_sub[cid].intersection(cluster_pub[other_cid]))

        exposers = set()
        for node, pubs in cluster_nodes_perms[cid]["pub"].items():
            if external_pub_perms.intersection(pubs):
                exposers.add(node)

        subscribers = set()
        for node, subs in cluster_nodes_perms[cid]["sub"].items():
            if external_sub_perms.intersection(subs):
                subscribers.add(node)

        enclave_exposers[cid] = exposers
        enclave_subscribers[cid] = subscribers

    report = f"""
Clustering Report:
- Number of clusters: {num_clusters}
- Average cluster size: {avg_cluster_size:.2f}
- Average intra-cluster Jaccard distance: {avg_intra_cluster_distance:.4f}

Trade-off between security and performance can be managed by tuning clustering threshold.

Enclave Nodes:
"""

    for cid in cluster_ids:
        nodes_list = sorted(clusters_dict[cid])
        report += f"- Cluster {cid} nodes (count {len(nodes_list)}):\n"
        for node in nodes_list:
            report += f"  {node}\n"

    report += "\nInter-Enclave Communication Flows:\n"

    if communication_flows:
        for flow in communication_flows:
            report += f"- From cluster {flow['from']} to cluster {flow['to']}:\n"
            if flow["topics"]:
                report += f"  Topics: {', '.join(flow['topics'])}\n"
            if flow["services"]:
                report += f"  Services: {', '.join(flow['services'])}\n"
            if flow["actions"]:
                report += f"  Actions: {', '.join(flow['actions'])}\n"
    else:
        report += "No detected communication flows between enclaves.\n"

    report += "\nNodes Exposing Permissions to External Entities Per Enclave:\n"
    for cid in cluster_ids:
        exposers_list = sorted(enclave_exposers[cid])
        if exposers_list:
            report += f"- Cluster {cid} exposers:\n"
            for node in exposers_list:
                report += f"  {node}\n"
        else:
            report += f"- Cluster {cid} exposers: None\n"

    report += "\nNodes Subscribing to External Entities Per Enclave:\n"
    for cid in cluster_ids:
        subscribers_list = sorted(enclave_subscribers[cid])
        if subscribers_list:
            report += f"- Cluster {cid} subscribers:\n"
            for node in subscribers_list:
                report += f"  {node}\n"
        else:
            report += f"- Cluster {cid} subscribers: None\n"

    return report