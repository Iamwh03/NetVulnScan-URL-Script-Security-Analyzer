import time
import wmi
from backend import HybridDetectionEngine

# Initialize your command‐analysis engine
engine = HybridDetectionEngine()

# Connect to the local WMI provider
c = wmi.WMI()

# Watch for *all* new processes; you can filter on ProcessName='powershell.exe' if you only care about PowerShell
process_watcher = c.Win32_Process.watch_for("creation")

print("[*] Watching for new processes… (Ctrl-C to stop)")
while True:
    try:
        new_proc = process_watcher()
        cmdline = new_proc.CommandLine or ""
        pname  = new_proc.Name or ""
        pid    = new_proc.ProcessId

        # Only examine PowerShell, wscript/cscript, or any background hosting host you care about:
        if pname.lower() in ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe"):
            print(f"\n[+] Detected {pname} (PID {pid}):\n    {cmdline}")

            # Run your command-analysis engine
            findings = engine.analyze(cmdline)
            ml = findings.get("machine_learning", [])
            rule_cats = [c for c in findings if c not in ("whitelisted","machine_learning")]

            # Simple alert logic
            malicious_votes = sum(1 for x in ml if x["prediction"]=="Malicious")
            if malicious_votes >= len(ml)/2 or len(rule_cats)>0:
                print(">>> ALERT: Malicious or Suspicious invocation detected!")
                for f in ml:
                    print(f"    • {f['model']} → {f['prediction']} ({f['confidence']:.1f}%)")
                for cat, items in findings.items():
                    if cat not in ("machine_learning","whitelisted"):
                        for item in items:
                            print(f"    • Rule {cat}: matched `{item['evidence']}`")
            else:
                print("    → Looks benign.")

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        break
    except Exception as e:
        # WMI watcher can occasionally glitch; just resume watching
        print(f"[!] Error in watcher loop: {e}")
        time.sleep(1)
