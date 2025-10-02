# main.py
# Final version with fully functional "Details" popup for command models.

import tkinter as tk
from tkinter import scrolledtext, font, ttk, Toplevel, messagebox
import threading
import time
from PIL import Image, ImageTk
import webbrowser
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns

# Import from your backend file
from backend import HybridDetectionEngine, URLDetectionEngine, query_virustotal_api, query_urlscan


class MalCommandGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MalwareCommandGuard Analyzer v12.2 (Final)")
        self.root.geometry("1200x800")

        self.setup_styles()
        self.root.configure(bg=self.BG_COLOR)

        try:
            self.command_engine = HybridDetectionEngine()
            self.url_engine = URLDetectionEngine()
            self.create_main_widgets()
        except Exception as e:
            error_label = ttk.Label(self.root, text=f"FATAL ERROR: Could not initialize engine.\n{e}", foreground="red",
                                    background=self.BG_COLOR)
            error_label.pack(expand=True, pady=20)

    def setup_styles(self):
        # ... (This section is complete and correct) ...
        self.BG_COLOR = "#202124"
        self.FRAME_BG = "#282A2E"
        self.TEXT_COLOR = "#E8EAED"
        self.ACCENT_COLOR = "#9D8854"
        self.ENTRY_BG = "#323639"
        self.BORDER_COLOR = "#444"
        self.SUBTLE_TEXT = "#9AA0A6"
        self.title_font = font.Font(family="Segoe UI Variable", size=18, weight="bold")
        self.header_font = font.Font(family="Segoe UI Variable", size=12, weight="bold")
        self.default_font = font.Font(family="Segoe UI Variable", size=10)
        self.verdict_font = font.Font(family="Segoe UI Variable", size=24, weight="bold")
        self.summary_font = font.Font(family="Segoe UI Variable", size=10, slant="italic")
        self.mono_font = font.Font(family="Consolas", size=9)
        self.VERDICT_COLORS = {"MALICIOUS": "#D9534F", "SUSPICIOUS": self.ACCENT_COLOR, "BENIGN": "#5CB85C",
                               "IDLE": "#4a4a4a"}
        self.URL_VERDICT_COLORS = {"Malware": "#D9534F", "Phishing": "#f0ad4e", "Defacement": "#5bc0de",
                                   "Benign": "#5CB85C"}
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=self.BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", background="#333", padding=[12, 6], font=("Segoe UI", 10, "bold"),
                        foreground="#aaa", borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", self.FRAME_BG)],
                  foreground=[("selected", self.ACCENT_COLOR)])
        style.configure("TFrame", background=self.FRAME_BG)
        style.configure("Content.TFrame", background=self.BG_COLOR)
        style.configure("Tab.TFrame", background=self.FRAME_BG)
        style.configure("TLabelFrame", background=self.FRAME_BG, bordercolor=self.BORDER_COLOR, relief="solid",
                        borderwidth=1)
        style.configure("TLabelFrame.Label", background=self.FRAME_BG, foreground=self.TEXT_COLOR,
                        font=self.header_font)
        style.configure("TLabel", background=self.FRAME_BG, foreground=self.TEXT_COLOR)
        style.configure("Subtle.TLabel", background=self.FRAME_BG, foreground=self.SUBTLE_TEXT)
        style.configure("TButton", padding=6, font=("Segoe UI", 10, "bold"), background=self.ACCENT_COLOR,
                        foreground="black", borderwidth=0, relief="flat")
        style.map("TButton", background=[('active', '#CAB287')])
        style.configure("TEntry", fieldbackground=self.ENTRY_BG, foreground=self.TEXT_COLOR,
                        bordercolor=self.BORDER_COLOR, insertcolor=self.TEXT_COLOR, borderwidth=1, relief="solid")

    def create_main_widgets(self):
        main_container = ttk.Frame(self.root, padding=20, style="Content.TFrame")
        main_container.pack(fill="both", expand=True)
        title_label = ttk.Label(main_container, text="MalwareCommandGuard Analyzer", font=self.title_font,
                                style="TLabel", background=self.BG_COLOR)
        title_label.pack(anchor="w", pady=(0, 20))
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill="both", expand=True)
        self.command_tab = ttk.Frame(self.notebook, padding=15, style="Tab.TFrame")
        self.url_tab = ttk.Frame(self.notebook, padding=15, style="Tab.TFrame")
        self.notebook.add(self.command_tab, text="Command Analysis")
        self.notebook.add(self.url_tab, text="URL Analysis")
        self.create_command_tab_widgets()
        self.create_url_tab_widgets()

    def create_command_tab_widgets(self):
        self.command_tab.grid_columnconfigure(0, weight=1)
        self.command_tab.grid_columnconfigure(1, weight=1)
        self.command_tab.grid_rowconfigure(1, weight=1)
        input_frame = ttk.Frame(self.command_tab, style="Tab.TFrame")
        input_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        self.command_input = ttk.Entry(input_frame, font=self.default_font)
        self.command_input.pack(fill="x", expand=True, side="left", ipady=5)
        analyze_cmd_button = ttk.Button(input_frame, text="Analyze Command", command=self.run_command_analysis)
        analyze_cmd_button.pack(side="left", padx=(10, 0))
        report_container = ttk.Frame(self.command_tab, style="TFrame")
        report_container.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        report_container.grid_rowconfigure(1, weight=1)
        report_container.grid_columnconfigure(0, weight=1)
        self.verdict_label = tk.Label(report_container, text="IDLE", font=self.verdict_font, fg="white",
                                      bg=self.VERDICT_COLORS["IDLE"], padx=15, pady=5)
        self.verdict_label.grid(row=0, column=0, pady=(0, 10), sticky="w")
        self.results_text = scrolledtext.ScrolledText(report_container, wrap=tk.WORD, font=self.default_font,
                                                      bg=self.ENTRY_BG, fg=self.TEXT_COLOR,
                                                      insertbackground=self.TEXT_COLOR, relief="solid", borderwidth=1)
        self.results_text.grid(row=1, column=0, sticky="nsew")
        self.results_text.tag_config('title', font=self.header_font, spacing3=5)
        self.results_text.tag_config('summary', font=self.summary_font, lmargin1=10, lmargin2=10, spacing3=10,
                                     foreground="#ccc")
        self.results_text.tag_config('metric', font=("Segoe UI", 10, "bold"), foreground=self.ACCENT_COLOR, spacing3=5)
        self.results_text.tag_config('whitelist', font=("Segoe UI", 10, "bold"), foreground="#5CB85C", spacing3=5)
        self.results_text.tag_config('evidence', lmargin1=20, lmargin2=20, font=self.mono_font)
        self.results_text.config(state="disabled")
        ml_container = ttk.Frame(self.command_tab, style="TFrame")
        ml_container.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
        self.ml_panel_frame = ttk.LabelFrame(ml_container, text="Machine Learning Panel", padding=10)
        self.ml_panel_frame.pack(fill="both", expand=True)
        ttk.Label(self.ml_panel_frame, text="Analysis results will appear here.", style="Subtle.TLabel").pack()

    def run_command_analysis(self):
        command = self.command_input.get()
        if not command: return
        findings = self.command_engine.analyze(command)
        ml_findings = findings.get('machine_learning', [])
        self.display_ml_panel(ml_findings, command)
        is_whitelisted = 'whitelisted' in findings
        score_fraction = sum(self.command_engine.score_weights.get(cat, 0) for cat in findings if
                             cat not in ['whitelisted', 'machine_learning'])
        rule_score_percentage = score_fraction * 100
        malicious_votes = sum(1 for f in ml_findings if f['prediction'] == 'Malicious')
        verdict = "BENIGN"
        if ml_findings and malicious_votes >= len(ml_findings) / 2:
            verdict = "MALICIOUS"
        elif rule_score_percentage > 70:
            verdict = "MALICIOUS"
        elif malicious_votes > 0 or rule_score_percentage > 20:
            verdict = "SUSPICIOUS"
        if is_whitelisted and verdict != 'MALICIOUS': verdict = "BENIGN"
        self.display_command_report(command, findings, verdict, rule_score_percentage)

    def display_ml_panel(self, ml_findings, command):
        for widget in self.ml_panel_frame.winfo_children(): widget.destroy()
        if not ml_findings:
            ttk.Label(self.ml_panel_frame, text="No ML analysis results for this command.",
                      style="Subtle.TLabel").pack()
            return
        for i, result in enumerate(ml_findings):
            frame = ttk.Frame(self.ml_panel_frame, style="TFrame", padding=10, relief="solid", borderwidth=1)
            frame.grid(row=i, column=0, sticky="ew", pady=10, padx=5)
            frame.grid_columnconfigure((0, 1, 2), weight=1)
            ttk.Label(frame, text=result['model'], font=self.header_font).grid(row=0, column=0, columnspan=3,
                                                                               sticky="w", pady=(0, 10))
            verdict = result['prediction']
            verdict_color = self.VERDICT_COLORS["MALICIOUS"] if verdict == 'Malicious' else self.VERDICT_COLORS[
                "BENIGN"]
            confidence_text = f"{result['confidence']:.2f}%" if result['confidence'] > 0 else "N/A"
            details_btn = ttk.Button(frame, text="Details", width=8,
                                     command=lambda m=result['model'], c=command: self.show_model_popup(m, c))
            details_btn.grid(row=1, column=0, sticky="w", padx=5)
            tk.Label(frame, text=verdict.upper(), bg=verdict_color, fg="white", font=("Segoe UI", 13, "bold"), padx=12,
                     pady=8).grid(row=1, column=1, sticky="ew", padx=5)
            tk.Label(frame, text=confidence_text, bg=verdict_color, fg="white", font=("Segoe UI", 13, "bold"), padx=12,
                     pady=8).grid(row=1, column=2, sticky="ew", padx=5)

    def show_model_popup(self, model_name, command):
        # This is the fully implemented pop-up function for command models
        popup = Toplevel(self.root)
        popup.title(f"Model Details: {model_name}")
        popup.geometry("640x520")
        popup.configure(bg=self.FRAME_BG)
        metrics = self.command_engine.metrics.get(model_name)
        model = self.command_engine.models.get(model_name)
        vectorizer = self.command_engine.vectorizer

        if metrics:
            # Display Confusion Matrix Plot
            plot_path = metrics.get('plot_path')
            try:
                img = Image.open(plot_path)
                img.thumbnail((350, 350))
                photo = ImageTk.PhotoImage(img)
                img_label = ttk.Label(popup, image=photo, background=self.FRAME_BG)
                img_label.image = photo
                img_label.pack(pady=10)
            except Exception as e:
                ttk.Label(popup, text=f"Could not display plot: {e}", foreground='red').pack(pady=10)

            # Display Classification Report
            report_frame = ttk.LabelFrame(popup, text="Overall Model Performance", padding=10)
            report_frame.pack(fill='x', padx=10, pady=10)
            report = metrics.get('classification_report', {}).get('1', {})  # Focus on 'Malicious' class
            scores = f"Precision: {report.get('precision', 0):.2f}\nRecall: {report.get('recall', 0):.2f}\nF1 Score: {report.get('f1-score', 0):.2f}"
            tk.Label(report_frame, text=scores, font=("Segoe UI", 11), bg=self.FRAME_BG, fg=self.TEXT_COLOR,
                     justify='left').pack(pady=5)
        else:
            tk.Label(popup, text="No evaluation metrics available for this model.", bg=self.FRAME_BG,
                     fg=self.TEXT_COLOR).pack(pady=20)

        # Display Real-time prediction
        if model and vectorizer:
            try:
                cmd_vec = vectorizer.transform([command])
                prediction = model.predict(cmd_vec)[0]
                proba = model.predict_proba(cmd_vec)[0]
                verdict = "Malicious" if prediction == 1 else "Benign"
                confidence = proba[1] * 100 if prediction == 1 else proba[0] * 100
                label = tk.Label(popup, text=f"Real-Time Verdict for this command: {verdict} ({confidence:.2f}%)",
                                 font=("Segoe UI", 12, "bold"), fg=self.VERDICT_COLORS[verdict.upper()],
                                 bg=self.FRAME_BG)
                label.pack(pady=(10, 5))
            except Exception as e:
                print(f"Error during real-time popup prediction: {e}")

    def display_command_report(self, command, findings, verdict, rule_score):
        self.verdict_label.config(text=verdict, bg=self.VERDICT_COLORS[verdict])
        self.results_text.config(state="normal")
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Scores\n", 'title')
        self.results_text.insert(tk.END, f"  Rule-Based Risk Score: {rule_score:.1f}%\n\n")
        summary = self.generate_analyst_summary(findings, verdict)
        self.results_text.insert(tk.END, "Analyst Summary\n", 'title')
        self.results_text.insert(tk.END, f"{summary}\n\n", "summary")
        self.results_text.insert(tk.END, "Rule-Based Detailed Findings\n", 'title')
        rule_findings = {k: v for k, v in findings.items() if k != 'machine_learning'}
        if not rule_findings:
            self.results_text.insert(tk.END, "  No rule-based indicators detected.\n")
        else:
            for category, finding_list in rule_findings.items():
                tag = 'whitelist' if category == 'whitelisted' else 'metric'
                self.results_text.insert(tk.END, f"METRIC: {category.upper()}\n", tag)
                for finding in finding_list:
                    self.results_text.insert(tk.END,
                                             f"  - Evidence: '{finding['evidence']}' (Matched Rule: '{finding['pattern']}')\n",
                                             'evidence')
        self.results_text.config(state="disabled")

    def generate_analyst_summary(self, findings, verdict):
        rule_categories = {cat for cat in findings if cat not in ['whitelisted', 'machine_learning']}
        ml_detected = any(f['prediction'] == 'Malicious' for f in findings.get('machine_learning', []))
        summary = f"This command is rated {verdict}. "
        if ml_detected and not rule_categories:
            summary += "The verdict is based primarily on the consensus from the ML models."
        elif rule_categories and not ml_detected:
            summary += f"The verdict is based on {len(rule_categories)} rule-based metric(s)."
        elif rule_categories and ml_detected:
            summary += f"The verdict is based on a consensus from {len(rule_categories)} rule-based metric(s) and the ML models."
        else:
            summary = "The command appears benign based on all available metrics."
        return summary

    def create_url_tab_widgets(self):
        input_frame = ttk.Frame(self.url_tab)
        input_frame.pack(fill="x", pady=(0, 15), anchor="n")
        self.url_input = ttk.Entry(input_frame, font=self.default_font)
        self.url_input.pack(fill="x", expand=True, side="left", ipady=5)
        analyze_url_button = ttk.Button(input_frame, text="Analyze URL", command=self.run_url_analysis)
        analyze_url_button.pack(side="left", padx=(10, 0))
        self.local_ml_frame = ttk.LabelFrame(self.url_tab, text="Local Machine Learning Analysis", padding=10)
        self.local_ml_frame.pack(fill="x", expand=False, anchor="n", pady=(0, 15))
        ttk.Label(self.local_ml_frame, text="Local model verdicts will appear here.", style="Subtle.TLabel").pack()
        self.api_results_frame = ttk.LabelFrame(self.url_tab, text="Internet Threat Intelligence (APIs)", padding=10)
        self.api_results_frame.pack(fill="both", expand=True, anchor="n")
        ttk.Label(self.api_results_frame, text="Enter a URL to begin API analysis.", style="Subtle.TLabel").pack()

    def run_url_analysis(self):
        url = self.url_input.get()
        if not url: return
        for widget in self.local_ml_frame.winfo_children(): widget.destroy()
        for widget in self.api_results_frame.winfo_children(): widget.destroy()
        local_findings = self.url_engine.analyze(url)
        self.display_local_url_report(local_findings, url)
        loading_label = ttk.Label(self.api_results_frame, text=f"Checking external APIs for {url}...", style="TLabel")
        loading_label.pack(pady=10)
        threading.Thread(target=self._url_analysis_thread, args=(url,), daemon=True).start()

    def _url_analysis_thread(self, url):
        # Use the new function name and signature
        vt_result = query_virustotal_api(url)
        urlscan_result = query_urlscan(url)
        self.root.after(0, self.display_api_url_report, vt_result, urlscan_result)

    def display_local_url_report(self, findings, url):
        for widget in self.local_ml_frame.winfo_children(): widget.destroy()
        if not findings:
            ttk.Label(self.local_ml_frame, text="Local ML Engine not enabled or no findings.",
                      style="Subtle.TLabel").pack()
            return
        for i, result in enumerate(findings):
            model_frame = ttk.Frame(self.local_ml_frame, padding=(0, 5))
            model_frame.pack(fill='x', pady=5)
            ttk.Label(model_frame, text=f"{result['model']}:", font=self.header_font).grid(row=0, column=0,
                                                                                           columnspan=3, sticky="w",
                                                                                           pady=(0, 5))
            details_btn = ttk.Button(model_frame, text="Details", width=8,
                                     command=lambda m=result['model'], u=url: self.show_url_model_popup(m, u))
            details_btn.grid(row=1, column=0, sticky="w", padx=(0, 10))
            verdict = result['prediction']
            color = self.URL_VERDICT_COLORS.get(verdict, "#777777")
            tk.Label(model_frame, text=verdict.upper(), bg=color, fg="white", font=("Segoe UI", 10, "bold"), padx=8,
                     pady=4).grid(row=1, column=1, sticky="w")
            confidence_text = f"{result['confidence']:.1f}% Confidence"
            ttk.Label(model_frame, text=confidence_text, foreground=self.SUBTLE_TEXT).grid(row=1, column=2, sticky="w",
                                                                                           padx=(10, 0))

    def show_url_model_popup(self, model_name, url):
        popup = Toplevel(self.root)
        popup.title(f"URL Model Details: {model_name}")
        popup.geometry("640x580")
        popup.configure(bg=self.FRAME_BG)

        # 1) Grab metrics that we pre-loaded from CSV
        metrics = self.url_engine.metrics.get(model_name, {})

        # 2) Confusion matrix
        if 'confusion_matrix' in metrics:
            fig, ax = plt.subplots(figsize=(5, 4), facecolor=self.FRAME_BG)
            ax.set_facecolor(self.FRAME_BG)
            cm = np.array(metrics['confusion_matrix'])
            labels = sorted(self.url_engine.label_map.values())
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                        xticklabels=labels, yticklabels=labels, ax=ax)
            ax.set_title("Confusion Matrix", color=self.TEXT_COLOR)
            ax.tick_params(colors=self.SUBTLE_TEXT)
            canvas = FigureCanvasTkAgg(fig, master=popup)
            canvas.draw()
            canvas.get_tk_widget().pack(pady=10)
        else:
            ttk.Label(popup, text="No confusion matrix available.",
                      background=self.FRAME_BG, foreground='red').pack(pady=10)

        # 3) Classification report
        if 'classification_report' in metrics:
            rpt = metrics['classification_report']  # dict of dicts
            rpt_frame = ttk.LabelFrame(popup, text="Classification Report", padding=10)
            rpt_frame.pack(fill='both', padx=10, pady=(0, 10))

            cols = ("Precision", "Recall", "F1-Score", "Support")
            tree = ttk.Treeview(rpt_frame, columns=cols, show="headings", height=len(rpt))
            for c in cols:
                tree.heading(c, text=c)
                tree.column(c, width=100, anchor="center")

            for label, scores in rpt.items():
                tree.insert("", "end", text=label,
                            values=(f"{scores.get('precision', 0):.2f}",
                                    f"{scores.get('recall', 0):.2f}",
                                    f"{scores.get('f1-score', 0):.2f}",
                                    f"{int(scores.get('support', 0))}"))
            tree.pack(fill='both', expand=False)
        else:
            ttk.Label(popup, text="No classification report available.",
                      background=self.FRAME_BG, foreground='red').pack(pady=10)

    def _create_clickable_link(self, parent, text, url):
        link_label = ttk.Label(parent, text=text, foreground="#66B2FF", cursor="hand2", font=self.default_font)
        link_label.pack(anchor="w", pady=(0, 10))
        link_label.bind("<Button-1>", lambda e: webbrowser.open_new(url))
        return link_label

    def display_api_url_report(self, vt_result, urlscan_result):
        for widget in self.api_results_frame.winfo_children():
            widget.destroy()
        vt_frame = ttk.LabelFrame(self.api_results_frame, text="VirusTotal Verdict", padding=10)
        vt_frame.pack(fill="x", expand=False, anchor="n", pady=(0, 15))
        if vt_result and not vt_result.get('error'):
            malicious_count = vt_result.get('malicious', 0)
            color = "#D9534F" if malicious_count > 0 else (
                "#f0ad4e" if vt_result.get('suspicious', 0) > 0 else "#5CB85C")
            verdict_text = f"Malicious: {malicious_count} / {vt_result.get('total_engines', 0)} engines"
            ttk.Label(vt_frame, text=verdict_text, foreground=color, font=self.header_font).pack(anchor="w")
            if vt_result.get('link'):
                self._create_clickable_link(vt_frame, "View Full Report on VirusTotal", vt_result.get('link'))
        else:
            ttk.Label(vt_frame, text=f"Error: {vt_result.get('error', 'Unknown error') if vt_result else 'No result'}",
                      foreground="red").pack(anchor="w")
        urlscan_frame = ttk.LabelFrame(self.api_results_frame, text="URLScan.io Intelligence", padding=10)
        urlscan_frame.pack(fill="both", expand=True, anchor="n")
        if urlscan_result and not urlscan_result.get('error'):
            info_text = (f"Domain: {urlscan_result.get('domain', 'N/A')}\n"
                         f"Server: {urlscan_result.get('server', 'N/A')}\n"
                         f"Verdict Score: {urlscan_result.get('verdict_score', 0)}\n"
                         f"Categories: {', '.join(urlscan_result.get('categories', [])) or 'None'}")
            ttk.Label(urlscan_frame, text=info_text, justify='left').pack(anchor="w", pady=(0, 10))
            if urlscan_result.get('urlscan_link'):
                self._create_clickable_link(urlscan_frame, "View Full Report on URLScan.io",
                                            urlscan_result.get('urlscan_link'))
        else:
            ttk.Label(urlscan_frame,
                      text=f"Error: {urlscan_result.get('error', 'Unknown error') if urlscan_result else 'No result'}",
                      foreground="red").pack(anchor="w")


if __name__ == "__main__":
    root = tk.Tk()
    app = MalCommandGuardApp(root)
    root.mainloop()