import os
import requests
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

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


def interactive_chat(raw_code, gnn_status, file_ext, initial_report):
    console.print(Panel.fit("[bold yellow]💬 DePatch-AI INTERACTIVE SECURITY ASSISTANT INITIATED[/bold yellow]\n[dim](Type 'exit' or 'quit' to terminate)[/dim]", border_style="yellow"))

    messages = [
        {"role": "system", "content": f"You are DePatch-AI  SAST Auditor. Ext: {file_ext}, GNN: {gnn_status}.\nCode:\n{raw_code}\nReport:\n{initial_report}"},
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

            with console.status("[bold cyan]DePatch-AI Engine thinking..."):
                response_content = ""
                api_key = os.getenv("OPENROUTER_API_KEY")
                if api_key:
                    try:
                        res = requests.post(
                            "https://openrouter.ai/api/v1/chat/completions",
                            json={"model": "poolside/laguna-xs-2.1", "messages": messages},
                            headers={"Authorization": f"Bearer {api_key.strip()}"},
                            timeout=45
                        )
                        if res.status_code == 200: response_content = res.json()['choices'][0]['message']['content']
                    except Exception: pass

                if not response_content:
                    try:
                        res_local = requests.post(
                            "http://localhost:11434/api/chat",
                            json={"model": "deepseek-coder:1.3b", "messages": messages, "stream": False},
                            timeout=90
                        )
                        if res_local.status_code == 200: response_content = res_local.json()['message']['content']
                    except Exception: response_content = "❌ Offline/Online Core pipeline failed."

            console.print(Panel(Markdown(response_content), title="[bold cyan]🤖 DePatch-AI Response[/bold cyan]", border_style="cyan"))
            messages.append({"role": "assistant", "content": response_content})
        except KeyboardInterrupt:
            break
