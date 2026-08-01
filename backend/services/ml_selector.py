"""
Rule-Based PQC Algorithm Smart Selector.

Pure-Python deterministic decision-tree ensemble, walking a hand-authored
140-row rule table, that selects the optimal PQC algorithm for a given scan
environment based on:
  - Pillar Type (Web, VPN, API, Mobile, Firmware, Archival)
  - Bandwidth Constraints (kbps)
  - Latency Sensitivity (ms)
  - Device Type (Server, Mobile, IoT, HSM)
  - Data Retention (years)
  - Compliance Mandate (CERT-In, RBI, NIST)

Decision Data: a hand-authored rule table encoding NIST PQC selection guidance
(FIPS 203 / 204 / 205 parameter sets) against deployment constraints. It is not
collected or observed data, and no external dataset is loaded at runtime.

Output: Algorithm selection with Selector_Log.
"""

from datetime import datetime
from typing import Optional


# ── Decision Table ────────────────────────────────────────────────────────────
# Hand-authored rows mapping deployment constraints to a PQC algorithm choice.
# Each row encodes published algorithm characteristics (key/signature sizes and
# security levels from FIPS 203/204/205) rather than any measured or collected
# dataset. Treat this as an expert-authored rule set, not training data.
#
# Features: [pillar_idx, bandwidth_kbps, latency_ms, device_idx,
#             retention_years, compliance_idx]
# Label:    algorithm index into ALGO_LABELS

ALGO_LABELS = [
    "ML-KEM-768",       # 0
    "ML-KEM-1024",      # 1
    "ML-DSA-65",        # 2
    "ML-DSA-87",        # 3
    "SLH-DSA-128f",     # 4
    "FN-DSA-512",       # 5
    "FN-DSA-1024",      # 6
    "XMSS-SHA2_10_256", # 7
    "LMS-SHA256_M32_H10", # 8
    "BIKE-L1",          # 9
    "HQC-128",          # 10
    "ML-KEM-512",       # 11
    "SLH-DSA-256s",     # 12
]

PILLAR_MAP = {
    "web": 0, "web/tls": 0,
    "vpn": 1, "vpn/tls": 1,
    "api": 2, "api/tls": 2,
    "mobile": 3, "mobile/app": 3,
    "firmware": 4, "system": 4, "system/firmware": 4,
    "archival": 5, "archival/storage": 5, "storage": 5,
}

DEVICE_MAP = {
    "server": 0,
    "mobile": 1,
    "iot": 2,
    "hsm": 3,
    "desktop": 0,
    "gateway": 0,
}

COMPLIANCE_MAP = {
    "cert-in": 0,
    "rbi": 1,
    "nist": 2,
    "dst": 0,
    "certin": 0,
}

# ── Rule Table ───────────────────────────────────────────────────────────────
# Format: (pillar_idx, bandwidth_kbps, latency_ms, device_idx,
#           retention_years, compliance_idx, label_idx)
# The bandwidth/latency figures are representative network tiers chosen by hand
# to span the range (fibre / broadband / rural / mobile). They are illustrative
# constraint boundaries, not measurements from any ISP dataset.

RULE_TABLE = [
    # ── Web/TLS (pillar=0): ML-KEM for key exchange ──
    (0, 100000, 4, 0, 1, 0, 0),    # High-BW fibre server → ML-KEM-768
    (0, 100000, 3, 0, 1, 2, 0),    # High-BW server NIST → ML-KEM-768
    (0, 50000, 8, 0, 1, 0, 0),     # Decent BW server → ML-KEM-768
    (0, 10000, 45, 0, 1, 0, 11),   # Low-BW rural server → ML-KEM-512 (low BW)
    (0, 5000, 80, 0, 1, 0, 11),    # Very low BW → ML-KEM-512
    (0, 200000, 2, 0, 5, 1, 1),    # Ultra-high BW, long retention → ML-KEM-1024
    (0, 150000, 3, 0, 3, 0, 1),    # High BW CERT-In → ML-KEM-1024
    (0, 80000, 5, 0, 1, 0, 0),     # Standard Indian DC → ML-KEM-768
    (0, 30000, 15, 1, 1, 0, 0),    # Mobile browsing → ML-KEM-768
    (0, 8000, 60, 2, 1, 0, 11),    # IoT gateway → ML-KEM-512
    (0, 120000, 4, 0, 1, 0, 0),
    (0, 90000, 6, 0, 1, 1, 0),
    (0, 60000, 10, 0, 2, 0, 0),
    (0, 15000, 35, 0, 1, 0, 11),
    (0, 250000, 1, 0, 7, 2, 1),
    (0, 180000, 2, 3, 5, 1, 1),    # HSM high-BW → ML-KEM-1024
    (0, 40000, 20, 0, 1, 0, 0),
    (0, 25000, 25, 1, 1, 0, 0),
    (0, 7000, 70, 2, 1, 0, 11),
    (0, 95000, 5, 0, 1, 0, 0),

    # ── VPN/TLS (pillar=1): ML-KEM for tunnel key exchange ──
    (1, 100000, 4, 0, 1, 0, 0),    # High-BW fibre VPN → ML-KEM-768
    (1, 50000, 10, 0, 1, 0, 0),    # Standard VPN → ML-KEM-768
    (1, 10000, 40, 0, 1, 0, 11),   # Low BW VPN → ML-KEM-512
    (1, 200000, 2, 0, 5, 1, 1),    # High-sec VPN → ML-KEM-1024
    (1, 30000, 20, 0, 1, 0, 0),    # Branch office VPN → ML-KEM-768
    (1, 5000, 100, 2, 1, 0, 11),   # IoT VPN → ML-KEM-512
    (1, 150000, 3, 0, 3, 2, 1),    # NIST high-sec → ML-KEM-1024
    (1, 80000, 8, 0, 1, 0, 0),
    (1, 60000, 12, 0, 1, 0, 0),
    (1, 20000, 30, 0, 1, 0, 0),
    (1, 120000, 4, 0, 2, 0, 0),
    (1, 40000, 18, 0, 1, 0, 0),
    (1, 8000, 55, 0, 1, 0, 11),
    (1, 180000, 2, 3, 5, 1, 1),
    (1, 70000, 7, 0, 1, 0, 0),
    (1, 15000, 36, 0, 1, 0, 11),
    (1, 95000, 5, 0, 1, 0, 0),
    (1, 110000, 4, 0, 1, 2, 0),
    (1, 45000, 14, 0, 1, 0, 0),
    (1, 6000, 75, 2, 1, 0, 11),

    # ── API/TLS (pillar=2): ML-DSA for signatures, SLH-DSA for backup ──
    (2, 100000, 4, 0, 1, 0, 2),    # Standard API → ML-DSA-65
    (2, 50000, 10, 0, 1, 0, 2),    # Standard API → ML-DSA-65
    (2, 200000, 2, 0, 5, 1, 3),    # High-sec API → ML-DSA-87
    (2, 150000, 3, 3, 10, 0, 12),  # HSM high-value → SLH-DSA-256s (backup)
    (2, 80000, 5, 0, 1, 0, 2),     # Normal API → ML-DSA-65
    (2, 100000, 4, 3, 7, 1, 4),    # HSM + RBI → SLH-DSA-128f (backup)
    (2, 30000, 20, 0, 1, 0, 2),    # Low-BW API → ML-DSA-65
    (2, 10000, 40, 1, 1, 0, 5),    # Mobile API → FN-DSA-512 (small sigs)
    (2, 60000, 8, 0, 1, 0, 2),
    (2, 120000, 3, 0, 3, 2, 3),    # NIST high-sec → ML-DSA-87
    (2, 40000, 15, 0, 1, 0, 2),
    (2, 90000, 5, 0, 1, 0, 2),
    (2, 180000, 2, 3, 8, 1, 12),   # HSM archival → SLH-DSA-256s
    (2, 70000, 7, 0, 1, 0, 2),
    (2, 20000, 25, 1, 1, 0, 5),    # Mobile API → FN-DSA-512
    (2, 5000, 60, 1, 1, 0, 5),     # Low-BW mobile → FN-DSA-512
    (2, 110000, 4, 0, 2, 0, 2),
    (2, 250000, 1, 3, 15, 2, 12),  # Critical HSM → SLH-DSA-256s
    (2, 45000, 12, 0, 1, 0, 2),
    (2, 85000, 6, 0, 1, 0, 2),

    # ── Mobile/App (pillar=3): FN-DSA for compact signatures ──
    (3, 30000, 25, 1, 1, 0, 5),    # Mid-BW mobile → FN-DSA-512
    (3, 10000, 50, 1, 1, 0, 5),    # Low-BW mobile → FN-DSA-512
    (3, 50000, 15, 1, 1, 0, 5),    # Wi-Fi mobile → FN-DSA-512
    (3, 5000, 80, 1, 1, 0, 5),     # 3G fallback → FN-DSA-512
    (3, 100000, 5, 1, 3, 1, 6),    # High-BW mobile, RBI → FN-DSA-1024
    (3, 80000, 8, 1, 1, 0, 5),     # Good mobile → FN-DSA-512
    (3, 2000, 120, 1, 1, 0, 5),    # Rural 2G → FN-DSA-512
    (3, 150000, 3, 1, 5, 2, 6),    # Wi-Fi 6 + NIST → FN-DSA-1024
    (3, 20000, 35, 1, 1, 0, 5),
    (3, 40000, 18, 1, 1, 0, 5),
    (3, 15000, 40, 1, 1, 0, 5),
    (3, 60000, 12, 1, 1, 0, 5),
    (3, 8000, 55, 1, 1, 0, 5),
    (3, 3000, 90, 1, 1, 0, 5),
    (3, 120000, 4, 1, 3, 1, 6),    # High-BW + RBI → FN-DSA-1024
    (3, 70000, 10, 1, 1, 0, 5),
    (3, 25000, 30, 1, 1, 0, 5),
    (3, 45000, 16, 1, 1, 0, 5),
    (3, 90000, 6, 1, 2, 0, 6),     # High BW + retention → FN-DSA-1024
    (3, 35000, 22, 1, 1, 0, 5),

    # ── System/Firmware (pillar=4): XMSS/LMS for integrity ──
    (4, 100000, 4, 0, 10, 0, 7),   # Server firmware → XMSS
    (4, 50000, 10, 0, 10, 0, 7),   # Standard firmware → XMSS
    (4, 200000, 2, 3, 15, 1, 7),   # HSM firmware → XMSS
    (4, 10000, 40, 2, 10, 0, 8),   # IoT firmware → LMS (simpler)
    (4, 5000, 80, 2, 10, 0, 8),    # Low-BW IoT → LMS
    (4, 80000, 5, 0, 10, 0, 7),    # DC firmware → XMSS
    (4, 30000, 20, 2, 10, 0, 8),   # IoT gateway → LMS
    (4, 150000, 3, 0, 15, 2, 7),   # NIST-compliant → XMSS
    (4, 60000, 8, 0, 10, 0, 7),
    (4, 120000, 4, 3, 10, 1, 7),   # HSM → XMSS
    (4, 40000, 15, 0, 10, 0, 7),
    (4, 20000, 30, 2, 10, 0, 8),   # IoT → LMS
    (4, 8000, 50, 2, 10, 0, 8),
    (4, 180000, 2, 0, 20, 1, 7),
    (4, 70000, 7, 0, 10, 0, 7),
    (4, 15000, 35, 2, 10, 0, 8),
    (4, 90000, 5, 0, 10, 0, 7),
    (4, 250000, 1, 3, 20, 2, 7),
    (4, 45000, 12, 0, 10, 0, 7),
    (4, 3000, 100, 2, 10, 0, 8),

    # ── Archival/Storage (pillar=5): BIKE/HQC for long-term encryption ──
    (5, 100000, 4, 0, 25, 0, 9),   # Standard archival → BIKE-L1
    (5, 50000, 10, 0, 25, 0, 9),   # Mid-BW → BIKE-L1
    (5, 200000, 2, 0, 50, 1, 10),  # Ultra-long retention → HQC-128
    (5, 10000, 40, 0, 25, 0, 9),   # Low-BW → BIKE-L1
    (5, 150000, 3, 3, 30, 2, 10),  # HSM long-term → HQC-128
    (5, 80000, 5, 0, 25, 0, 9),    # Normal DC → BIKE-L1
    (5, 30000, 20, 0, 25, 0, 9),   # Branch → BIKE-L1
    (5, 120000, 4, 0, 40, 1, 10),  # RBI long-term → HQC-128
    (5, 60000, 8, 0, 25, 0, 9),
    (5, 180000, 2, 3, 50, 2, 10),  # HSM + NIST ultra-long → HQC-128
    (5, 40000, 15, 0, 25, 0, 9),
    (5, 5000, 60, 0, 25, 0, 9),
    (5, 250000, 1, 0, 50, 1, 10),
    (5, 90000, 5, 0, 25, 0, 9),
    (5, 70000, 7, 0, 30, 0, 10),   # 30yr → HQC-128
    (5, 20000, 25, 0, 25, 0, 9),
    (5, 110000, 4, 0, 25, 0, 9),
    (5, 15000, 35, 0, 25, 0, 9),
    (5, 140000, 3, 0, 40, 1, 10),
    (5, 8000, 50, 0, 25, 0, 9),

    # ── Cross-pillar edge cases (mixed) ──
    (0, 3000, 150, 2, 1, 0, 11),   # Ultra-low BW IoT web → ML-KEM-512
    (1, 3000, 120, 2, 1, 0, 11),   # Ultra-low BW IoT VPN → ML-KEM-512
    (2, 3000, 100, 1, 1, 0, 5),    # Ultra-low BW mobile API → FN-DSA-512
    (3, 200000, 1, 1, 5, 2, 6),    # Ultra-high BW mobile → FN-DSA-1024
    (4, 1000, 200, 2, 10, 0, 8),   # Ultra-constrained IoT → LMS
    (5, 300000, 1, 3, 75, 2, 10),  # HSM ultra-archival → HQC-128
    (2, 15000, 30, 1, 1, 0, 5),    # Mobile API moderate → FN-DSA-512
    (0, 300000, 1, 3, 10, 2, 1),   # HSM ultra-high web → ML-KEM-1024
    (1, 250000, 1, 3, 10, 1, 1),   # HSM ultra-high VPN → ML-KEM-1024
    (2, 200000, 2, 0, 1, 0, 3),    # High BW API → ML-DSA-87

    # ── Additional Indian network profiles ──
    (0, 75000, 7, 0, 1, 0, 0),     # Mid-BWFiber → ML-KEM-768
    (0, 12000, 42, 0, 1, 0, 11),   # Low-BWbroadband → ML-KEM-512
    (1, 75000, 7, 0, 1, 0, 0),     # Mid-BWVPN → ML-KEM-768
    (1, 12000, 42, 0, 1, 0, 11),   # Low-BWVPN → ML-KEM-512
    (2, 75000, 7, 0, 1, 0, 2),     # Mid-BWAPI → ML-DSA-65
    (3, 12000, 42, 1, 1, 0, 5),    # Low-BWmobile → FN-DSA-512
    (2, 12000, 42, 0, 1, 0, 2),    # Low-BWAPI → ML-DSA-65
    (3, 75000, 7, 1, 1, 0, 5),     # Mid-BWmobile → FN-DSA-512
    (0, 55000, 9, 0, 1, 0, 0),     # ACT Fiber → ML-KEM-768
    (1, 55000, 9, 0, 1, 0, 0),     # ACT VPN → ML-KEM-768
]


# ── Pure-Python Decision Tree ─────────────────────────────────────────────────

class _DecisionNode:
    """Internal node or leaf in a decision tree."""
    __slots__ = ("feature", "threshold", "left", "right", "label")

    def __init__(self, feature=None, threshold=None, left=None, right=None, label=None):
        self.feature = feature
        self.threshold = threshold
        self.left = left
        self.right = right
        self.label = label

    def predict(self, x: list) -> int:
        if self.label is not None:
            return self.label
        if x[self.feature] <= self.threshold:
            return self.left.predict(x)
        return self.right.predict(x)


def _gini(groups: list, classes: set) -> float:
    """Calculate Gini impurity for a split."""
    total = sum(len(g) for g in groups)
    if total == 0:
        return 0.0
    score = 0.0
    for group in groups:
        size = len(group)
        if size == 0:
            continue
        s = 0.0
        for c in classes:
            p = sum(1 for row in group if row[-1] == c) / size
            s += p * p
        score += (1.0 - s) * (size / total)
    return score


def _best_split(data: list, n_features: int) -> tuple:
    """Find the best split point across all features."""
    classes = set(row[-1] for row in data)
    best_feat, best_thresh, best_score, best_groups = None, None, 999.0, None

    for feat_idx in range(n_features):
        values = sorted(set(row[feat_idx] for row in data))
        for i in range(len(values) - 1):
            thresh = (values[i] + values[i + 1]) / 2.0
            left = [row for row in data if row[feat_idx] <= thresh]
            right = [row for row in data if row[feat_idx] > thresh]
            g = _gini([left, right], classes)
            if g < best_score:
                best_feat, best_thresh, best_score, best_groups = feat_idx, thresh, g, (left, right)

    return best_feat, best_thresh, best_groups


def _majority(data: list) -> int:
    """Return the most common label."""
    counts: dict[int, int] = {}
    for row in data:
        counts[row[-1]] = counts.get(row[-1], 0) + 1
    return max(counts, key=counts.get)


def _build_tree(data: list, n_features: int, max_depth: int, depth: int = 0) -> _DecisionNode:
    """Recursively build a decision tree."""
    classes = set(row[-1] for row in data)
    if len(classes) == 1:
        return _DecisionNode(label=data[0][-1])
    if depth >= max_depth or len(data) <= 2:
        return _DecisionNode(label=_majority(data))

    feat, thresh, groups = _best_split(data, n_features)
    if feat is None or groups is None:
        return _DecisionNode(label=_majority(data))

    left_node = _build_tree(groups[0], n_features, max_depth, depth + 1)
    right_node = _build_tree(groups[1], n_features, max_depth, depth + 1)
    return _DecisionNode(feature=feat, threshold=thresh, left=left_node, right=right_node)


class _RuleTreeEnsemble:
    """Deterministic decision-tree ensemble over a hand-authored rule table.

    Each tree is built from a deterministic strided subset of the rule table
    (not a random bootstrap sample), so results are fully reproducible: the
    same inputs always walk the same tree paths and produce the same vote.
    """

    def __init__(self, n_trees: int = 3, max_depth: int = 6):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees: list[_DecisionNode] = []

    def fit(self, data: list, n_features: int):
        """Build ensemble trees from deterministic strided subsets of the rule table."""
        n = len(data)
        for i in range(self.n_trees):
            # Deterministic stride sampling (not bootstrap/bagging): the
            # offset and stride vary per tree so each tree sees a different
            # deterministic ordering of the same rule table.
            stride = max(1, n // (self.n_trees + i))
            sample = [data[(j * stride + i * 7) % n] for j in range(n)]
            tree = _build_tree(sample, n_features, self.max_depth)
            self.trees.append(tree)

    def predict(self, x: list) -> tuple:
        """Predict with majority vote. Returns (label, confidence)."""
        votes: dict[int, int] = {}
        for tree in self.trees:
            pred = tree.predict(x)
            votes[pred] = votes.get(pred, 0) + 1
        winner = max(votes, key=votes.get)
        confidence = votes[winner] / len(self.trees)
        return winner, confidence


# ── Build the ensemble at import time (deterministic, fast) ───────────────────

_model = _RuleTreeEnsemble(n_trees=3, max_depth=6)
_model.fit(RULE_TABLE, n_features=6)

# Which label(s) are actually valid for each pillar, derived from the rule
# table itself. The tree's splits are learned over all 6 features jointly, so
# an input combination the training rows never pair with that pillar (e.g.
# pillar=Mobile with the UI's Server/1yr defaults, when every Mobile row in
# RULE_TABLE has device=Mobile) can land on a leaf from a different pillar's
# branch entirely — e.g. predicting ML-DSA-65 for "Mobile", while the
# rationale text below is keyed on pillar and still describes FN-DSA. Used as
# a consistency guard so the returned algorithm and its rationale can never
# describe two different algorithm families.
_PILLAR_LABELS: dict[int, list[int]] = {}
for _row in RULE_TABLE:
    _PILLAR_LABELS.setdefault(_row[0], []).append(_row[-1])


def _majority_label_for_pillar(pillar_idx: int) -> Optional[int]:
    labels = _PILLAR_LABELS.get(pillar_idx)
    if not labels:
        return None
    counts: dict[int, int] = {}
    for l in labels:
        counts[l] = counts.get(l, 0) + 1
    return max(counts, key=counts.get)


# ── Feature Descriptions (for Selector_Log) ──────────────────────────────────

FEATURE_NAMES = [
    "Pillar Type", "Bandwidth (kbps)", "Latency (ms)",
    "Device Type", "Data Retention (years)", "Compliance Mandate",
]

PILLAR_NAMES = ["Web/TLS", "VPN/TLS", "API/TLS", "Mobile/App", "System/Firmware", "Archival/Storage"]
DEVICE_NAMES = ["Server", "Mobile", "IoT", "HSM"]
COMPLIANCE_NAMES = ["CERT-In", "RBI", "NIST"]


# ── Public API ────────────────────────────────────────────────────────────────

def select_algorithm(
    pillar: str,
    bandwidth_kbps: int = 50000,
    latency_ms: int = 10,
    device_type: str = "Server",
    retention_years: int = 1,
    compliance: str = "CERT-In",
) -> dict:
    """
    Select the optimal PQC algorithm for the given scan environment.

    Returns a dict with:
      algorithm, parameter_set, confidence, selector_log, rationale,
      network_profile, compliance_mandate, timestamp
    """
    pillar_idx = PILLAR_MAP.get(pillar.lower().strip(), 0)
    device_idx = DEVICE_MAP.get(device_type.lower().strip(), 0)
    compliance_idx = COMPLIANCE_MAP.get(compliance.lower().strip(), 0)

    features = [pillar_idx, bandwidth_kbps, latency_ms, device_idx, retention_years, compliance_idx]

    label_idx, confidence = _model.predict(features)

    # Consistency guard: the rationale text below is keyed purely on pillar_idx,
    # so if the ensemble's vote landed on a label that RULE_TABLE never actually
    # pairs with this pillar, fall back to this pillar's majority label rather
    # than return an algorithm whose family contradicts its own rationale.
    valid_labels = _PILLAR_LABELS.get(pillar_idx)
    if valid_labels and label_idx not in valid_labels:
        fallback = _majority_label_for_pillar(pillar_idx)
        if fallback is not None:
            label_idx = fallback
            confidence = round(_PILLAR_LABELS[pillar_idx].count(fallback) / len(_PILLAR_LABELS[pillar_idx]), 2)
    algorithm = ALGO_LABELS[label_idx]

    # Parse algorithm into family + parameter set
    parts = algorithm.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        family = parts[0]
        param = algorithm
    else:
        family = algorithm
        param = algorithm

    # Build network characteristics string
    pillar_name = PILLAR_NAMES[pillar_idx] if pillar_idx < len(PILLAR_NAMES) else pillar
    device_name = DEVICE_NAMES[device_idx] if device_idx < len(DEVICE_NAMES) else device_type
    compliance_name = COMPLIANCE_NAMES[compliance_idx] if compliance_idx < len(COMPLIANCE_NAMES) else compliance

    network_chars = (
        f"{pillar_name} pillar, {bandwidth_kbps} kbps bandwidth, "
        f"{latency_ms}ms latency, {device_name} device, "
        f"{retention_years}yr retention, {compliance_name} mandate"
    )

    selector_log = (
        f"Algorithm [{algorithm}] selected via rule-based decision-tree ensemble based on "
        f"[{network_chars}]."
    )

    # Build rationale
    rationale_parts = []
    if pillar_idx in (0, 1):
        rationale_parts.append("Key exchange required for TLS/VPN tunnel establishment.")
        if bandwidth_kbps < 15000:
            rationale_parts.append("Low bandwidth favors smaller key sizes (ML-KEM-512).")
        elif bandwidth_kbps > 150000 and retention_years > 3:
            rationale_parts.append("High bandwidth and long retention support Level-5 security (ML-KEM-1024).")
    elif pillar_idx == 2:
        rationale_parts.append("Digital signature required for API authentication and JWT signing.")
        if device_idx == 1:
            rationale_parts.append("Mobile device favors compact signatures (FN-DSA).")
        elif device_idx == 3 and retention_years > 5:
            rationale_parts.append("HSM with long retention triggers conservative backup (SLH-DSA).")
    elif pillar_idx == 3:
        rationale_parts.append("Mobile presence requires minimal signature overhead.")
        rationale_parts.append("FN-DSA provides smallest signature sizes among lattice schemes.")
    elif pillar_idx == 4:
        rationale_parts.append("Firmware integrity requires stateful hash-based signatures.")
        if device_idx == 2:
            rationale_parts.append("IoT constraints favor LMS over XMSS for simpler state management.")
    elif pillar_idx == 5:
        rationale_parts.append("Long-term archival encryption requires code-based KEMs.")
        if retention_years > 30:
            rationale_parts.append("Ultra-long retention (>30yr) favors HQC for conservative security margin.")

    rationale_parts.append(f"DST PQC Migration Roadmap alignment: {compliance_name} compliant.")

    return {
        "algorithm": algorithm,
        "parameter_set": param,
        "confidence": round(confidence, 2),
        "selector_log": selector_log,
        "rationale": " ".join(rationale_parts),
        "network_profile": {
            "pillar": pillar_name,
            "bandwidth_kbps": bandwidth_kbps,
            "latency_ms": latency_ms,
            "device_type": device_name,
            "retention_years": retention_years,
            "compliance": compliance_name,
        },
        "model_info": {
            "type": "Deterministic Decision-Tree Ensemble",
            "n_trees": _model.n_trees,
            "max_depth": _model.max_depth,
            "training_samples": len(RULE_TABLE),
            "training_source": "Hand-authored rule table derived from NIST FIPS 203/204/205 parameter sets",
            "external_dataset": False,
        },
        "timestamp": datetime.utcnow().isoformat(),
    }
