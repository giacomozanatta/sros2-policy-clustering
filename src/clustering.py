import numpy as np
from scipy.spatial.distance import pdist, squareform
from scipy.cluster.hierarchy import linkage, fcluster

def build_global_permission_set(profiles_permissions):
    global_permissions = set()
    for perms in profiles_permissions.values():
        global_permissions.update(perms)
    return sorted(global_permissions)

def permissions_to_bitvector(permissions, global_permissions):
    bitvector = np.zeros(len(global_permissions), dtype=int)
    perm_index = {p: i for i, p in enumerate(global_permissions)}
    for p in permissions:
        if p in perm_index:
            bitvector[perm_index[p]] = 1
    return bitvector

def compute_jaccard_distance_matrix(bitvectors):
    bool_vectors = np.array(bitvectors, dtype=bool)
    dists = pdist(bool_vectors, metric='jaccard')
    dist_matrix = squareform(dists)
    return dist_matrix

def hierarchical_clustering(dist_matrix, threshold=0.5):
    linkage_matrix = linkage(dist_matrix, method='average')
    clusters = fcluster(linkage_matrix, t=threshold, criterion='distance')
    return clusters