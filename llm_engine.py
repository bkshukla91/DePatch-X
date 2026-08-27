import os
import json
import requests

# ==========================================
# 4. Hybrid Cloud & Local LLM Auditor Engine
# ==========================================
def get_cloud_audit(raw_code, gnn_status, file_ext):
    api_key = os.getenv("OPENROUTER_API_KEY")
    url_cloud = "https://openrouter.ai/api/v1/chat/completions"
    url_local = "http://localhost:11434/api/chat"

    safe_code = raw_code.encode("ascii", "ignore").decode("ascii")
    prompt = (
        f"You are DeepSpy SAST Auditor. GNN flagged code triage as: {gnn_status}.\n\n"
        f"Analyze this raw script and provide a precise vulnerability report in Markdown format with:\n"
        f"1. VULNERABILITY DETAILS & LOCATION\n"
        f"2. ROOT CAUSE & EXPLOIT MECHANICS\n"
        f"3. SECURE REWRITE PATCH (inside standard markdown code fence)\n"
        f"4. FUTURE PROACTIVE ADVICE\n\n"
        f"Target Code:\n{safe_code}"
    )

    if api_key:
        headers_cloud = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json"
        }
        payload_cloud = {
            "model": "poolside/laguna-xs-2.1",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        try:
            console.print("[yellow][☁️] Attempting Cloud Core Audit...[/yellow]")
            res = requests.post(url_cloud, json=payload_cloud, headers=headers_cloud, timeout=45)
            if res.status_code == 200:
                console.print("[bold green][✅] Cloud Audit Successful![/bold green]")
                return res.json()['choices'][0]['message']['content']
        except Exception as e:
            console.print(f"[orange3][⚠️] Cloud Connection Failed: {str(e)}[/orange3]")

    # Fallback to local
    console.print("[orange3][🦙] Switching to Local Offline Infrastructure...[/orange3]")
    payload_local = {
        "model": "deepseek-coder:1.3b",
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0.1}
    }
    try:
        res_local = requests.post(url_local, json=payload_local, timeout=90)
        if res_local.status_code == 200:
            console.print("[bold green][✅] Local Ollama Audit Successful![/bold green]")
            return res_local.json()['message']['content']
    except Exception as local_err:
        return f"❌ Critical Pipeline Failure: {str(local_err)}"

# ==========================================
# 5. Pipeline Core
# ==========================================
def run_core_pipeline(file_name, file_ext, raw_code):
    # [1/3] Parsing
    graph_data = generate_ast_graph(file_name, file_ext, raw_code)

    # [2/3] Embedding
    data = get_embeddings_and_data(graph_data)

    # [3/3] GNN Prediction via New Checkpoint (best_model.pt)
    MODEL_PATH = "best_model.pt"
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    if not os.path.exists(MODEL_PATH):
        return "🔴 VULNERABLE (best_model.pt Not Found fallback)", 50.0, raw_code, graph_data

    model = VulnerabilityGNN(in_channels=768, num_classes=2).to(device)

    try:
        model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    except Exception as e:
        console.print(f"[bold red]❌ Model checkpoint mismatch/error: {e}[/bold red]")
        return "🔴 VULNERABLE (Model Load Error)", 0.0, raw_code, graph_data

    model.eval()

    data = data.to(device)
    data.batch = torch.zeros(data.x.size(0), dtype=torch.long).to(device)

    with torch.no_grad():
        logits, _ = model(data)
        prediction = logits.argmax(dim=1).item()
        probabilities = F.softmax(logits, dim=1)
        confidence = probabilities[0][prediction].item() * 100

    if prediction == 1:
        status = "🔴 VULNERABLE"
    else:
        status = "🟢 SAFE"

    return status, confidence, raw_code, graph_data

# ==========================================
# 6. Interactive CLI Chat
# ==========================================
def interactive_chat(raw_code, gnn_status, file_ext, initial_report):
    console.print(Panel.fit("[bold yellow]💬 DEEPSPY INTERACTIVE SECURITY ASSISTANT INITIATED[/bold yellow]\n[dim](Type 'exit' or 'quit' to terminate)[/dim]", border_style="yellow"))

    messages = [
        {"role": "system", "content": f"You are DeepSpy SAST Auditor. Ext: {file_ext}, GNN: {gnn_status}.\nCode:\n{raw_code}\nReport:\n{initial_report}"},
        {"role": "assistant", "content": initial_report}
    ]

    while True:
        try:
            user_query = console.input("\n[bold green][🧑 User] > [/bold green]").strip()
            if not user_query: continue
            if user_query.lower() in ['exit', 'quit']:
                console.print("[bold red]Session Terminated. Stay Secure![/bold red]")
                break

            messages.append({"role": "user", "content": user_query})

            with console.status("[bold cyan]DeepSpy Engine thinking..."):
                response_content = ""
                api_key = os.getenv("OPENROUTER_API_KEY")
                if api_key:
                    try:
                        res = requests.post("https://openrouter.ai/api/v1/chat/completions", json={"model": "poolside/laguna-xs-2.1", "messages": messages}, headers={"Authorization": f"Bearer {api_key.strip()}"}, timeout=45)
                        if res.status_code == 200: response_content = res.json()['choices'][0]['message']['content']
                    except Exception: pass

                if not response_content:
                    try:
                        res_local = requests.post("http://localhost:11434/api/chat", json={"model": "deepseek-coder:1.3b", "messages": messages, "stream": False}, timeout=90)
                        if res_local.status_code == 200: response_content = res_local.json()['message']['content']
                    except Exception: response_content = "❌ Offline/Online Core pipeline failed."

            console.print(Panel(Markdown(response_content), title="[bold cyan]🤖 DeepSpy Response[/bold cyan]", border_style="cyan"))
            messages.append({"role": "assistant", "content": response_content})
        except KeyboardInterrupt:
            break

# ==========================================
# 7. Main Entry
# ==========================================
def main():
    if len(sys.argv) < 2:
        console.print("[bold red]Usage: python3 scan.py <path_to_file>[/bold red]")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        console.print(f"[bold red]❌ File {file_path} not found.[/bold red]")
        sys.exit(1)

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    console.print(Panel(f"[bold cyan]🔍 Target Detected:[/bold cyan] {os.path.basename(file_path)}\n[bold cyan]📁 File Ext:[/bold cyan] {ext}", title="DeepSpy Static Guard v2.0 (GATv2 Engine)", border_style="blue"))

    with open(file_path, 'r', encoding='utf-8') as f:
        raw_code = f.read()

    status, confidence, _, graph_data = run_core_pipeline(file_path, ext, raw_code)

    # Print AST / Graph Summary
    table = Table(title="Graph Structure Metrics", border_style="dim")
    table.add_column("Component", style="cyan")
    table.add_column("Count", style="magenta")
    table.add_row("Nodes", str(len(graph_data["nodes"])))
    table.add_row("Edges", str(len(graph_data["edges"])))
    console.print(table)

    style = "red" if "VULNERABLE" in status else "green"
    console.print(Panel(f"[bold {style}]RESULT: {status} (GNN Confidence: {confidence:.2f}%)[/bold {style}]", title="GNN Decision Layer", border_style=style))

    report = get_cloud_audit(raw_code, f"{status} (Confidence: {confidence:.2f}%)", ext)
    console.print(Panel(Markdown(report), title="Deep Security Audit Report", border_style="purple"))

    interactive_chat(raw_code, status, ext, report)

if __name__ == "__main__":
    main()
