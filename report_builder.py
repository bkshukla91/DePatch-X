"""
report_builder.py -- turns raw model output (label, confidence, per-node
attention importance) into a clean "findings" dict, used both for the
Rich console display and as grounding context for the LLM prompt.
"""


def build_findings(function_name, label, confidence, nodes, importance, code_lines, top_k=5):
    """
    nodes: list[NodeInfo] (aligned with `importance`, from graph_builder.py)
    code_lines: the source file's lines (0-indexed list; code_lines[line-1] for 1-indexed line)
    """
    all_lines = [n.line for n in nodes if n.line and n.line > 0]
    line_range = (min(all_lines), max(all_lines)) if all_lines else (0, 0)

    per_line = {}
    for node, score in zip(nodes, importance):
        if node.line and node.line > 0:
            if node.line not in per_line or score > per_line[node.line][0]:
                per_line[node.line] = (score, node.node_type, node.text)

    ranked_lines = sorted(per_line.items(), key=lambda kv: kv[1][0], reverse=True)[:top_k]

    # Normalize relative to this function's own top score, so the displayed
    # ranking is visually meaningful (top line = 1.00, others scaled below
    # it) instead of raw, hard-to-interpret sums.
    max_score = ranked_lines[0][1][0] if ranked_lines else 1.0
    max_score = max_score or 1.0  # avoid div-by-zero if every score is 0

    top_lines = []
    for line, (score, ntype, text) in ranked_lines:
        snippet = code_lines[line - 1].strip() if 0 < line <= len(code_lines) else text
        top_lines.append((line, score / max_score, snippet))

    return {
        "function_name": function_name,
        "label": label,
        "confidence": confidence,
        "top_lines": top_lines,
        "line_range": line_range,
    }
