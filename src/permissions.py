from lxml import etree

def extract_permissions_from_profile(profile_xml_root):
    permissions = set()
    
    for topics in profile_xml_root.findall(".//topics"):
        pub_allowed = topics.get("publish")
        sub_allowed = topics.get("subscribe")
        for topic in topics.findall("topic"):
            topic_name = topic.text.strip()
            if pub_allowed and pub_allowed.upper() == "ALLOW":
                permissions.add(f"pub:{topic_name}")
            if sub_allowed and sub_allowed.upper() == "ALLOW":
                permissions.add(f"sub:{topic_name}")

    for services in profile_xml_root.findall(".//services"):
        srv_allowed = services.get("allow")
        for service in services.findall("service"):
            service_name = service.text.strip()
            if srv_allowed and srv_allowed.upper() == "ALLOW":
                permissions.add(f"srv:{service_name}")

    for actions in profile_xml_root.findall(".//actions"):
        act_allowed = actions.get("allow")
        for action in actions.findall("action"):
            action_name = action.text.strip()
            if act_allowed and act_allowed.upper() == "ALLOW":
                permissions.add(f"act:{action_name}")

    for parameters in profile_xml_root.findall(".//parameters"):
        get_allowed = parameters.get("get")
        set_allowed = parameters.get("set")
        for param in parameters.findall("parameter"):
            param_name = param.text.strip()
            if get_allowed and get_allowed.upper() == "ALLOW":
                permissions.add(f"param_get:{param_name}")
            if set_allowed and set_allowed.upper() == "ALLOW":
                permissions.add(f"param_set:{param_name}")

    return permissions

def parse_policy_file(filepath):
    tree = etree.parse(filepath)
    root = tree.getroot()
    profiles = {}
    for profile in root.findall(".//profile"):
        node = profile.get("node")
        if node is None:
            continue
        perms = extract_permissions_from_profile(profile)
        profiles[node] = perms
    return profiles