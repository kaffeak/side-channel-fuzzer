"""Exploratory preparation-label classification, never cache-state truth or G3 acceptance.

Fit reads calibration sessions only. Evaluation uses separately held-out sessions.
Session bootstrap summarizes variation BETWEEN sessions, not independent raw loads.
"""
# pylint: disable=missing-function-docstring
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.cacheObservation import protocol


def quantile(values, percent):
    ordered = sorted(values)
    protocol.require(bool(ordered), "Empty distribution")
    return ordered[max(0, (percent * len(ordered) + 99) // 100 - 1)]


def summary(values):
    counts = Counter(values)
    return {"n": len(values), "zeros": values.count(0),
            "zero_fraction": {"numerator": values.count(0), "denominator": len(values)},
            "min": min(values), "p05": quantile(values, 5), "p50": quantile(values, 50),
            "p95": quantile(values, 95), "p99": quantile(values, 99), "max": max(values),
            "histogram": [[value, counts[value]] for value in sorted(counts)]}


def distributions(session):
    result = {}
    for series in protocol.SERIES:
        pairs = {}
        for label in (0, 1):
            values = [protocol.ticks(row["delta_ticks"]) for row in session["samples"]
                      if row["series"] == series and row["label"] == label]
            pairs[str(label)] = summary(values)
        # Ordered paired-block differences are descriptive, not independent replicates.
        by_block: dict[int, dict[int, int]] = {}
        for row in session["samples"]:
            if row["series"] == series:
                by_block.setdefault(row["block"], {})[row["label"]] = protocol.ticks(
                    row["delta_ticks"])
        differences = [pair[1] - pair[0] for pair in by_block.values()]
        result[series] = {"labels": pairs, "paired_block_difference": summary(differences)}
    return result


def signature(session):
    meta = session["metadata"]
    result = {key: meta[key] for key in (
        "platform", "commit", "source_sha256", "binary_sha256", "compiler", "kernel", "machine",
        "page_size", "blocks", "prep_bytes", "stride", "selected_cpu", "frequency_hz")}
    result["host_label"] = session["host_label"]
    protocol.require(isinstance(result["host_label"], str) and bool(result["host_label"]),
                     "Missing separately captured host label")
    return result


def identities(sessions):
    ids = [session["metadata"]["session"] for session in sessions]
    hashes = [session["raw_sha256"] for session in sessions]
    protocol.require(len(set(ids)) == len(ids) and len(set(hashes)) == len(hashes),
                     "Duplicate session identity/artifact")
    return ids, hashes


def fit(sessions):
    protocol.require(1 <= len(sessions) <= 32, "Use 1..32 calibration sessions")
    ids, hashes = identities(sessions)
    cohort = signature(sessions[0])
    protocol.require(all(signature(session) == cohort for session in sessions),
                     "Do not pool platforms, hosts, binaries, CPUs or preparation parameters")
    reports = [distributions(session) for session in sessions]
    centers = [quantile([report["ordered"]["labels"][str(label)]["p50"]
                         for report in reports], 50) for label in (0, 1)]
    return {"version": 1, "algorithm": "median-threshold-v1", "signature": cohort,
            "calibration_sessions": ids, "calibration_hashes": hashes,
            "threshold_ticks": None if centers[0] == centers[1] else sum(centers) // 2,
            "label_one_is_high": centers[1] > centers[0], "calibration_centers": centers,
            "calibration_distributions": reports, "g3_accepted": False}


def confusion(session, model, series):
    matrix = [[0, 0], [0, 0]]  # Actual operational label, predicted operational label.
    for row in session["samples"]:
        if row["series"] == series:
            high = protocol.ticks(row["delta_ticks"]) > model["threshold_ticks"]
            prediction = int(high == model["label_one_is_high"])
            matrix[row["label"]][prediction] += 1
    rates = [matrix[label][label] / sum(matrix[label]) for label in (0, 1)]
    return {"matrix_actual_by_prediction": matrix, "balanced_accuracy": sum(rates) / 2,
            "label0_as_label1": matrix[0][1], "label1_as_label0": matrix[1][0]}


def evaluate(model, sessions):
    protocol.require(set(model) == {"version", "algorithm", "signature", "calibration_sessions",
                                    "calibration_hashes", "threshold_ticks", "label_one_is_high",
                                    "calibration_centers", "calibration_distributions",
                                    "g3_accepted"},
                     "Unknown/missing frozen-model fields")
    protocol.require(protocol.integer(model["version"]) == 1
                     and model["algorithm"] == "median-threshold-v1",
                     "Unsupported frozen calibration artifact")
    protocol.require(isinstance(model["label_one_is_high"], bool), "Invalid orientation")
    ids, hashes = model["calibration_sessions"], model["calibration_hashes"]
    protocol.require(isinstance(ids, list) and isinstance(hashes, list)
                     and 1 <= len(ids) == len(hashes) <= 32, "Malformed calibration identities")
    protocol.require(all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", item)
                         for item in ids)
                     and all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
                             for item in hashes), "Malformed calibration provenance")
    protocol.require(len(set(ids)) == len(ids) and len(set(hashes)) == len(hashes),
                     "Duplicate calibration identities")
    centers = model["calibration_centers"]
    protocol.require(isinstance(centers, list) and len(centers) == 2, "Invalid calibration centers")
    for center in centers:
        protocol.integer(center)
    threshold = None if centers[0] == centers[1] else sum(centers) // 2
    protocol.require(model["threshold_ticks"] == threshold
                     and model["label_one_is_high"] == (centers[1] > centers[0])
                     and model["g3_accepted"] is False, "Contradictory frozen classifier")
    if model["threshold_ticks"] is not None:
        protocol.integer(model["threshold_ticks"])
    protocol.require(1 <= len(sessions) <= 32, "Use 1..32 held-out sessions")
    ids, hashes = identities(sessions)
    protocol.require(not set(ids) & set(model["calibration_sessions"])
                     and not set(hashes) & set(model["calibration_hashes"]),
                     "Calibration/held-out data overlap")
    protocol.require(all(signature(session) == model["signature"] for session in sessions),
                     "Held-out cohort differs from frozen calibration")
    report = {"g3_accepted": False, "outcome": "inconclusive", "physical_origin": "not_attested",
              "frozen_model_sha256": hashlib.sha256(
                  json.dumps(model, sort_keys=True).encode()).hexdigest(),
              "threshold_ticks": model["threshold_ticks"], "held_out_sessions": ids,
              "held_out_distributions": [distributions(session) for session in sessions],
              "uncertainty": None,
              "criterion": "Exploratory only; separate frozen G3 error/performance review required"}
    if model["threshold_ticks"] is None:
        report["reason"] = "Calibration session medians coincide; no classifier fitted"
        return report
    comparisons = [{series: confusion(session, model, series)
                    for series in protocol.SERIES} for session in sessions]
    report["per_session_classification"] = comparisons
    report["outcome"] = "exploratory" if len(sessions) >= 3 else "inconclusive"
    report["reason"] = "No G3 acceptance criterion tested"
    if len(sessions) >= 3:
        # Equal session weights; raw correlated observations are NEVER bootstrap units.
        generator = random.Random(1)
        intervals = {}
        for series in protocol.SERIES:
            accuracies = [item[series]["balanced_accuracy"] for item in comparisons]
            replicates = sorted(
                sum(generator.choices(accuracies, k=len(accuracies))) / len(accuracies)
                for _ in range(2000))
            intervals[series] = {
                "session_mean_balanced_accuracy": sum(accuracies) / len(accuracies),
                "session_bootstrap_percentile95": [replicates[49], replicates[1949]]}
        report["uncertainty"] = {"unit": "independently launched session (assumed, not proven)",
                                 "seed": 1, "replicates": 2000, "series": intervals,
                                 "limit": "Small-session interval, not a calibrated test"}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("fit", "evaluate", "describe"):
        command = sub.add_parser(action)
        command.add_argument("sessions", type=Path, nargs="+")
        command.add_argument("--output", type=Path, required=True)
        if action == "evaluate":
            command.add_argument("--model", type=Path, required=True)
    args = parser.parse_args()
    try:
        protocol.require(1 <= len(args.sessions) <= 32, "At most 32 session paths")
        sessions = [protocol.load_session(path) for path in args.sessions]
        if args.action == "fit":
            report = fit(sessions)
        elif args.action == "evaluate":
            report = evaluate(protocol.read_json(args.model), sessions)
        else:
            identities(sessions)
            report = {"sessions": [{"metadata": session["metadata"],
                                    "distributions": distributions(session)}
                                   for session in sessions],
                      "g3_accepted": False, "physical_origin": "not_attested"}
        serialized = json.dumps(report, sort_keys=True, indent=2) + "\n"
        protocol.require(len(serialized.encode()) <= protocol.MAX_BYTES,
                         "Derived artifact too large")
        with args.output.open("x") as file:
            file.write(serialized)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"REJECTED: {error}; retain all raw data", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
