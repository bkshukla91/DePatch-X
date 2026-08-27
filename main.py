"""
DePatch AI -- GNN-powered Static Application Security Testing (SAST) CLI.

Pipeline:
  source code -> Joern AST graphs (per function) -> trained GATv2 GNN
  -> attention-grounded XAI (which lines the model focused on)
  -> LLM-authored root-cause explanation, CWE classification & patch
  -> interactive follow-up chat
  -> colorful PDF report saved to disk

Currently scoped to C/C++ (that is what the underlying model was
trained on -- see build_dataset_v2.py / train_final_gnn_v2.py). Feeding
it other languages would produce unreliable, unvalidated predictions.
"""
import os
import sys
import zipfile
import tempfile

from dotenv import load_dotenv
load_dotenv()

import torch
from transformers import AutoTokenizer, AutoModel

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn
from rich.prompt import Prompt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.graph_builder import extract_functions, JoernError
from core.model import load_model, predict_function
from core.llm_auditor import get_cloud_audit, interactive_chat
from core.report_builder import build_findings
from core import pdf_report

TOOL_NAME = "DePatch AI"
MODEL_PATH = os.environ.get("MODEL_PATH", "best_model.pt")
SUPPORTED_EXT = (".c", ".h", ".cpp", ".cc", ".hpp", ".cxx")
REPORTS_DIR = os.environ.get("DEPATCH_REPORTS_DIR", "reports")
MAX_CHAT_TURNS = 6   # keep only the last N user/assistant exchanges, so a long
                      # chat session doesn't keep growing the prompt (and latency)

console = Console()


def print_banner():
    try:
        import pyfiglet
        art = pyfiglet.figlet_format("DePatch AI", font="slant")
        console.print(f"[bold cyan]{art}[/bold cyan]", highlight=False)
    except Exception:
        pass  # optional dependency -- falls through to the plain panel below
    console.print(Panel.fit(
        f"[bold cyan]{TOOL_NAME}[/bold cyan]  [dim]|[/dim]  GNN-Powered Source Code Security Auditor\n\n"
        "[bold yellow]Author : Balkrishna Shukla[/bold yellow]\n\n"
        "[bold green]Graph attention detection  \u2025  Explainable AI  \u2025  Automated patching  \u2025  Future Proactive Advice \u2025 Interactive Chat \u2025  C/C++[/bold green]",
        border_style="cyan", padding=(1, 4),
    ))


def load_engines():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    console.print("[bold cyan]Loading CodeBERT tokenizer + embedding table...[/bold cyan]")
    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    embed_model = AutoModel.from_pretrained("microsoft/codebert-base", use_safetensors=True)
    embed_model.eval()
    embedding_layer = embed_model.get_input_embeddings()

    if not os.path.exists(MODEL_PATH):
        console.print(f"[bold red]Model checkpoint not found at '{MODEL_PATH}'.[/bold red]\n"
                       f"Set MODEL_PATH in .env, or copy best_model.pt next to main.py.")
        sys.exit(1)

    console.print("[bold cyan]Loading trained DePatch-GNN checkpoint...[/bold cyan]")
    model = load_model(MODEL_PATH, device=str(device))
    console.print(f"[bold green]Ready.[/bold green] (device: {device})\n")
    return tokenizer, embedding_layer, model, device


def _targets_from_zip(zip_path):
    extract_dir = tempfile.mkdtemp(prefix="depatch_zip_")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extract_dir)
    targets = []
    for root, _, files in os.walk(extract_dir):
        for fn in files:
            if fn.lower().endswith(SUPPORTED_EXT):
                full = os.path.join(root, fn)
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        targets.append((os.path.relpath(full, extract_dir), f.read()))
                except Exception:
                    continue
    console.print(f"[dim]Extracted {len(targets)} C/C++ source file(s) from the zip.[/dim]")
    return targets


def get_source_targets():
    """Returns list of (display_name, source_code)."""
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if path.lower().endswith(".zip"):
            if not os.path.exists(path):
                console.print(f"[bold red]File not found: {path}[/bold red]")
                sys.exit(1)
            return _targets_from_zip(path)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [(os.path.basename(path), f.read())]
        console.print(f"[bold red]File not found: {path}[/bold red]")
        sys.exit(1)

    console.print("[bold]How would you like to provide code?[/bold]")
    console.print("  [cyan]1[/cyan]) Paste code directly")
    console.print("  [cyan]2[/cyan]) Path to a single file")
    console.print("  [cyan]3[/cyan]) Path to a .zip of a project")
    choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="1")

    if choice == "1":
        console.print("[dim]Paste your code, then press Enter followed by Ctrl+D "
                       "(Ctrl+Z then Enter on Windows) to finish:[/dim]")
        code = sys.stdin.read()
        return [("pasted_snippet.c", code)]

    if choice == "2":
        path = Prompt.ask("File path").strip().strip('"')
        if not os.path.exists(path):
            console.print(f"[bold red]File not found: {path}[/bold red]")
            sys.exit(1)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [(os.path.basename(path), f.read())]

    zip_path = Prompt.ask("Zip file path").strip().strip('"')
    if not os.path.exists(zip_path):
        console.print(f"[bold red]File not found: {zip_path}[/bold red]")
        sys.exit(1)
    return _targets_from_zip(zip_path)


def analyze_file(display_name, code, tokenizer, embedding_layer, model, device):
    results = []
    code_lines = code.splitlines()

    with Progress(
        SpinnerColumn(), TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=30), TaskProgressColumn(), TimeElapsedColumn(), console=console, transient=True,
    ) as progress:
        # Joern runs as a single opaque subprocess call, so a true percentage
        # isn't knowable -- we show a live elapsed-time counter instead of a
        # frozen spinner, so it's clear the tool is working, not stuck.
        t1 = progress.add_task(f"Running Joern static analysis on {display_name}... (usually 10-40s)", total=None)
        try:
            functions = extract_functions(code, tokenizer, embedding_layer, filename_hint=display_name)
        except JoernError as e:
            progress.stop()
            console.print(Panel(f"[red]{e}[/red]", title=f"Joern error -- {display_name}", border_style="red"))
            return results
        progress.remove_task(t1)

        if not functions:
            console.print(f"[yellow]No analyzable functions found in {display_name} "
                           f"(parse failed, or file too trivial).[/yellow]")
            return results

        t2 = progress.add_task(f"Running GNN inference ({len(functions)} function(s))...", total=len(functions))
        for fn in functions:
            label, confidence, importance = predict_function(model, fn.data, device=str(device))
            findings = build_findings(fn.name, label, confidence, fn.nodes, importance, code_lines)
            findings["source_file"] = display_name

            lo, hi = findings["line_range"]
            if lo and hi and hi >= lo:
                findings["function_code"] = "\n".join(code_lines[lo - 1:hi])
            else:
                findings["function_code"] = code

            results.append(findings)
            progress.advance(t2)

    return results


def display_summary_table(all_findings):
    table = Table(title="Scan Summary", border_style="dim")
    table.add_column("File", style="cyan")
    table.add_column("Function", style="white")
    table.add_column("Verdict")
    table.add_column("Confidence", justify="right")
    for f in all_findings:
        verdict = "[bold red]VULNERABLE[/bold red]" if f["label"] == 1 else "[bold green]SAFE[/bold green]"
        table.add_row(f["source_file"], f["function_name"], verdict, f"{f['confidence']:.2f}%")
    console.print(table)


def _report_panel(report_text, file_name, source_used, live=False):
    suffix = "" if live else "  [dim](finished)[/dim]"
    return Panel(
        Markdown(report_text or "...", code_theme="monokai"),
        title=f"Security Audit Report -- {file_name}  [dim](source: {source_used})[/dim]{suffix}",
        border_style="purple", padding=(1, 3), width=min(console.width, 110),
    )


def display_vulnerable_detail_combined(file_name, findings_list, raw_code, file_ext):
    """Shows every vulnerable function found in one file, then makes exactly
    ONE streamed LLM call covering all of them (text appears progressively
    instead of a long silent wait), and finally saves a colorful PDF copy."""
    names = ", ".join(f"{f['function_name']} ({f['confidence']:.1f}%)" for f in findings_list)
    console.print(Panel(
        f"[bold red]{len(findings_list)} vulnerable function(s) found[/bold red]\n{names}",
        title=f"⚠ {file_name}", border_style="red", padding=(1, 2),
    ))

    for findings in findings_list:
        lo, _ = findings["line_range"]
        highlight = {ln for ln, _, _ in findings["top_lines"]}
        console.print(f"\n[bold]Function:[/bold] {findings['function_name']}  "
                       f"[dim]({findings['confidence']:.2f}% confidence)[/dim]")
        if findings["function_code"].strip():
            console.print(Syntax(
                findings["function_code"], "c", theme="monokai", line_numbers=True,
                start_line=max(lo, 1), highlight_lines=highlight,
            ))
        if findings["top_lines"]:
            table = Table(title="Lines the model attended to most (real GNN attention, not a guess)",
                           border_style="dim", padding=(0, 1))
            table.add_column("Line", justify="right", style="yellow")
            table.add_column("Attention", justify="right")
            table.add_column("Code")
            for ln, score, snippet in findings["top_lines"]:
                table.add_row(str(ln) if ln > 0 else "?", f"{score:.2f}", snippet[:90])
            console.print(table)

    # -------------------------------------------------------------
    # 🚀 NEW INTEGRATION (get_cloud_audit & interactive_chat)
    # -------------------------------------------------------------
    gnn_status = f"🔴 VULNERABLE ({len(findings_list)} functions flagged)"
    
    report = get_cloud_audit(raw_code, gnn_status, file_ext)
    console.print(Panel(Markdown(report), title="Deep Security Audit Report", border_style="purple"))

    interactive_chat(raw_code, gnn_status, file_ext, report)  


def main():
    print_banner()
    tokenizer, embedding_layer, model, device = load_engines()
    targets = get_source_targets()

    all_findings = []
    for display_name, code in targets:
        if not code.strip():
            continue
        all_findings.extend(analyze_file(display_name, code, tokenizer, embedding_layer, model, device))

    if not all_findings:
        console.print("[yellow]No functions were successfully analyzed.[/yellow]")
        return

    display_summary_table(all_findings)

    vulnerable_count = sum(1 for f in all_findings if f["label"] == 1)
    if vulnerable_count == 0:
        console.print(Panel("[bold green]No vulnerabilities detected in the scanned code.[/bold green]",
                             border_style="green"))

    else:
        by_file = {}
        for f in all_findings:
            if f["label"] == 1:
                by_file.setdefault(f["source_file"], []).append(f)
                
        for file_name, findings_list in by_file.items():

            import os
            _, file_ext = os.path.splitext(file_name)
            
            raw_code = findings_list[0].get("file_code", "") 
            if not raw_code:
                try:
                    with open(file_name, "r", encoding="utf-8") as rf:
                        raw_code = rf.read()
                except Exception:
                    raw_code = "\n".join(f.get("function_code", "") for f in findings_list)

            display_vulnerable_detail_combined(file_name, findings_list, raw_code, file_ext)


if __name__ == "__main__":
    main()
