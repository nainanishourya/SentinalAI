"""Compares agent predictions against the scenario's known ground truth to
produce the 'prediction accuracy score' shown on the dashboard."""


def score_run(ground_truth_mitre: list[dict], predicted_techniques: list[dict], detected_category: str, true_category: str) -> dict:
    truth_ids = {t["technique_id"].split(".")[0] for t in ground_truth_mitre}
    pred_ids = set()
    for t in predicted_techniques or []:
        tid = str(t.get("technique_id", "")).strip()
        if tid:
            pred_ids.add(tid.split(".")[0])

    if truth_ids:
        overlap = truth_ids & pred_ids
        mitre_score = 100.0 * len(overlap) / len(truth_ids)
    else:
        mitre_score = 0.0

    category_score = 100.0 if detected_category and detected_category.lower() == (true_category or "").lower() else 40.0

    accuracy = round(0.65 * mitre_score + 0.35 * category_score, 1)
    accuracy = max(0.0, min(100.0, accuracy))

    return {
        "accuracy_score": accuracy,
        "mitre_overlap_score": round(mitre_score, 1),
        "category_match_score": round(category_score, 1),
        "matched_technique_ids": sorted(truth_ids & pred_ids),
        "missed_technique_ids": sorted(truth_ids - pred_ids),
    }
