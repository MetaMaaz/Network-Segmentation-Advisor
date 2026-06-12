"""segmentation-advisor: zero-trust network segmentation advisory engine.

Pipeline: discovery (or mock YAML) -> Inventory -> classifier -> recommender
-> attack_path -> reporter. Only ``discovery`` touches the network; everything
else is pure, offline-testable logic.
"""

__version__ = "1.0.0"
