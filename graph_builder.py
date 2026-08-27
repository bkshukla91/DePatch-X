"""
graph_builder.py -- turns raw C/C++ source into per-function graphs using
the EXACT SAME Joern export pipeline (repr=ast, format=dot) and the EXACT
SAME lightweight CodeBERT-embedding-table node features used when the
model was trained (see build_dataset_v2.py). This is not optional: the
model was trained on this specific feature distribution, and any drift
here (different embedding method, different graph structure) silently
produces meaningless predictions.
"""
import os
import re
import html
import glob
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

import torch
from torch_geometric.data import Data

JOERN_CLI_DIR = os.environ.get("JOERN_CLI_DIR", "/home/balkrishna/GNN_SecTool/joern/joern-cli")
JOERN_C2CPG = os.path.join(JOERN_CLI_DIR, "c2cpg.sh")
JOERN_EXPORT = os.path.join(JOERN_CLI_DIR, "joern-export")
C2CPG_TIMEOUT_SEC = 300
EXPORT_TIMEOUT_SEC = 180
NODE_TOKEN_MAX_LEN = 32

DIGRAPH_NAME_RE = re.compile(r'^digraph\s+"([^"]*)"\s*\{')
NODE_LINE_RE = re.compile(r'^"(\d+)"\s*\[label\s*=\s*<(.*)>\s*\]\s*$')
EDGE_LINE_RE = re.compile(r'"(\d+)"\s*->\s*"(\d+)"')


@dataclass
class NodeInfo:
    idx: int
    node_type: str
    text: str
    line: int   # -1 if unknown


@dataclass
class FunctionGraph:
    name: str
    data: Data
    nodes: list           # list[NodeInfo], aligned row-for-row with data.x
    source_file: str = ""


class JoernError(Exception):
    pass


def _run(cmd, timeout):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise JoernError(f"{' '.join(cmd)}\n{result.stderr[-1200:]}")
    except subprocess.TimeoutExpired:
        raise JoernError(f"Timed out after {timeout}s: {' '.join(cmd)}")
    except FileNotFoundError as e:
        raise JoernError(f"Executable not found: {e}. Check JOERN_CLI_DIR in your .env file.")


def _parse_ast_dot(path):
    method_name = None
    nodes = []
    edges = []
    id_map = {}
    fallback_name = None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if method_name is None:
                m = DIGRAPH_NAME_RE.match(line)
                if m:
                    method_name = html.unescape(m.group(1))
                    continue

            node_m = NODE_LINE_RE.match(line)
            if node_m:
                node_id, label_content = node_m.group(1), node_m.group(2)
                parts = label_content.split("<BR/>")
                head_bits = parts[0].split(",")
                node_type = html.unescape(head_bits[0].strip())

                line_no = -1
                if len(head_bits) > 1:
                    try:
                        line_no = int(head_bits[1].strip())
                    except ValueError:
                        line_no = -1

                rest = " ".join(parts[1:]) if len(parts) > 1 else node_type
                node_text = html.unescape(rest).strip() or node_type

                local_idx = len(nodes)
                id_map[node_id] = local_idx
                nodes.append(NodeInfo(idx=local_idx, node_type=node_type, text=node_text, line=line_no))

                if node_type == "METHOD" and fallback_name is None:
                    fallback_name = node_text
                continue

            if "->" in line:
                for src, dst in EDGE_LINE_RE.findall(line):
                    if src in id_map and dst in id_map:
                        edges.append((id_map[src], id_map[dst]))

    if method_name is None:
        method_name = fallback_name or "unknown"
    return method_name, nodes, edges


def _embed_node_texts(texts, tokenizer, embedding_layer, max_len):
    if len(texts) == 0:
        return torch.zeros((0, embedding_layer.embedding_dim))
    enc = tokenizer(texts, padding=True, truncation=True, max_length=max_len, return_tensors="pt")
    with torch.no_grad():
        tok_embeds = embedding_layer(enc["input_ids"])
        mask = enc["attention_mask"].unsqueeze(-1).float()
        summed = (tok_embeds * mask).sum(dim=1)
        counts = mask.sum(dim=1).clamp(min=1)
        return summed / counts


def extract_functions(source_code: str, tokenizer, embedding_layer,
                       filename_hint: str = "snippet.c",
                       min_nodes: int = 2, max_nodes: int = 3000):
    """Runs Joern on one piece of source code and returns a list of
    FunctionGraph, one per REAL function found in it."""
    work_root = tempfile.mkdtemp(prefix="depatch_")
    try:
        src_dir = os.path.join(work_root, "src")
        os.makedirs(src_dir, exist_ok=True)

        safe_name = os.path.basename(filename_hint) or "snippet.c"
        if not safe_name.lower().endswith((".c", ".h", ".cpp", ".cc", ".hpp", ".cxx")):
            safe_name += ".c"
        src_path = os.path.join(src_dir, safe_name)
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source_code)

        cpg_bin = os.path.join(work_root, "cpg.bin")
        export_dir = os.path.join(work_root, "export")

        _run([JOERN_C2CPG, src_dir, "--output", cpg_bin], timeout=C2CPG_TIMEOUT_SEC)
        if not os.path.exists(cpg_bin):
            raise JoernError("c2cpg.sh produced no cpg.bin (the code likely failed to parse as valid C/C++).")

        _run([JOERN_EXPORT, cpg_bin, "--repr=ast", "--format=dot", "--out", export_dir],
             timeout=EXPORT_TIMEOUT_SEC)
        if not os.path.isdir(export_dir):
            raise JoernError("joern-export produced no output directory.")

        results = []
        for dot_path in sorted(glob.glob(os.path.join(export_dir, "*.dot"))):
            method_name, nodes, edges = _parse_ast_dot(dot_path)

            # Joern emits synthetic pseudo-methods such as "<global>" (the
            # file-scope wrapper containing #includes/top-level statements/
            # comments) and internal placeholders like "<operator>",
            # "<empty>", "<unknown>", "<lambda>...". These are NOT real,
            # user-written functions and must never be shown as a
            # "detected" finding -- this was the root cause of duplicate/
            # garbage findings (e.g. a lone comment line reported as its
            # own "vulnerable function").
            if not method_name or method_name.startswith("<"):
                continue
            if not (min_nodes <= len(nodes) <= max_nodes) or len(edges) == 0:
                continue

            texts = [f"{n.node_type}: {n.text}" for n in nodes]
            x = _embed_node_texts(texts, tokenizer, embedding_layer, NODE_TOKEN_MAX_LEN)

            src_idx = [e[0] for e in edges] + [e[1] for e in edges]
            dst_idx = [e[1] for e in edges] + [e[0] for e in edges]   # bidirectional, matches training
            edge_index = torch.tensor([src_idx, dst_idx], dtype=torch.long)

            data = Data(x=x, edge_index=edge_index)
            results.append(FunctionGraph(name=method_name, data=data, nodes=nodes, source_file=filename_hint))

        return results
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
