#!/usr/bin/env python3
"""
Periodic retraining loop for anomaly baselines.
"""

import time
import os
from core.anomaly_detection import AnomalyDetector


def main():
    interval = int(os.getenv("VESTIGIA_RETRAIN_INTERVAL_SECONDS", "3600"))
    detector = AnomalyDetector()
    while True:
        detector.retrain()
        time.sleep(interval)


if __name__ == "__main__":
    main()
