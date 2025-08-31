# coding: utf-8
import requests
import json
import os
import threading
import queue
import time
import sys
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

# --- Interface Graphique ---
import tkinter as tk
from tkinter import scrolledtext, Button, Label, Frame, filedialog

# --- Génération PDF ---
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors

# --- Génération Graphiques ---
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from collections import Counter, defaultdict
from datetime import datetime

# --- Constants ---
CVE_URL_TEMPLATE = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/database/CVE-{year}.jsonl"
MITRE_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
NVD_API_URL_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
MITRE_CACHE_FILE = Path("enterprise-attack.json")
CACHE_DURATION_SECONDS = 7 * 24 * 60 * 60  # 7 jours

# --- Caching & Network Functions ---

def get_mitre_data_with_cache(log_queue: queue.Queue) -> Optional[Dict[str, Any]]:
    if MITRE_CACHE_FILE.exists() and (time.time() - MITRE_CACHE_FILE.stat().st_mtime) < CACHE_DURATION_SECONDS:
        log_queue.put("3. Loading MITRE ATT&CK database from local cache...")
        try:
            with open(MITRE_CACHE_FILE, 'r', encoding='utf-8') as f: return json.load(f)
        except json.JSONDecodeError as e: log_queue.put(f"ERROR: Could not read cached MITRE file. Will re-download. Details: {e}")
    log_queue.put("3. Downloading fresh MITRE ATT&CK database (will be cached)...")
    try:
        response = requests.get(MITRE_ATTACK_URL)
        response.raise_for_status()
        mitre_data = response.json()
        with open(MITRE_CACHE_FILE, 'w', encoding='utf-8') as f: json.dump(mitre_data, f)
        return mitre_data
    except requests.exceptions.RequestException as e:
        log_queue.put(f"CRITICAL ERROR downloading MITRE data: {e}"); return None

def download_jsonl(url: str, log_queue: queue.Queue) -> Optional[List[str]]:
    try:
        response = requests.get(url); response.raise_for_status(); return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        if e.response and e.response.status_code == 404: log_queue.put(f"WARNING: Database not found for the year at URL {url}")
        else: log_queue.put(f"ERROR downloading CVE file: {e}")
        return None

# --- Data Processing & Indexing ---

class MitreDataIndexer:
    def __init__(self, mitre_data: Dict[str, Any]):
        self.technique_by_external_id: Dict[str, Any] = {}
        self.item_by_internal_id: Dict[str, Any] = {}
        self.actors_map: Dict[str, Dict[str, str]] = {}
        for item in mitre_data.get('objects', []):
            self.item_by_internal_id[item.get('id', '')] = item
            if item.get('type') == 'attack-pattern':
                for ref in item.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack': self.technique_by_external_id[ref.get('external_id')] = item
            elif item.get('type') in ['intrusion-set', 'campaign']: self.actors_map[item.get('id', '')] = {'name': item.get('name', 'Unknown Actor')}
    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        item = self.technique_by_external_id.get(technique_id)
        if not item: return None
        full_desc = item.get('description', 'No description available.').replace('\n', '<br/>')
        short_desc = full_desc.split('<br/><br/>')[0]
        url = next((ref.get('url', '#') for ref in item.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), '#')
        return {"id": item.get('id'), "technique_id": technique_id, "name": item.get('name', 'Unnamed'), "short_description": short_desc, "url": url, "kill_chain_phases": item.get('kill_chain_phases', [])}
    def map_techniques_to_actors(self, techniques_info: List[Dict[str, Any]], log_queue: queue.Queue) -> Dict[str, List[str]]:
        log_queue.put("   -> Correlating techniques with threat actors...")
        tech_internal_id_map = {info['id']: info['technique_id'] for info in techniques_info}
        actor_to_techs = defaultdict(list)
        for rel in self.item_by_internal_id.values():
            if rel.get('type') == 'relationship' and rel.get('relationship_type') == 'uses':
                source_id, target_id = rel.get('source_ref'), rel.get('target_ref')
                if source_id in self.actors_map and target_id in tech_internal_id_map:
                    actor_to_techs[self.actors_map[source_id]['name']].append(tech_internal_id_map[target_id])
        for actor in actor_to_techs: actor_to_techs[actor] = sorted(list(set(actor_to_techs[actor])))
        return dict(sorted(actor_to_techs.items()))

# --- CVSS Score Function (Hybrid: Batch with Individual Fallback) ---

def get_single_cvss_score(cve_id: str) -> str:
    """Helper function to get score for a single CVE. Used as a fallback."""
    try:
        response = requests.get(f"{NVD_API_URL_BASE}{cve_id}", timeout=10)
        if response.status_code == 404: return "Not Found in NVD"
        response.raise_for_status()
        data = response.json()
        metrics = data['vulnerabilities'][0]['cve']['metrics']
        cvss_metrics = metrics.get('cvssMetricV31', [])
        if cvss_metrics:
            metric = cvss_metrics[0]['cvssData']
            return f"{metric.get('baseScore')} ({metric.get('baseSeverity')})"
        return "CVSS v3.1 N/A"
    except (requests.exceptions.RequestException, KeyError, IndexError):
        return "Error"

def get_cvss_scores_batch(cve_ids: List[str], log_queue: queue.Queue) -> Dict[str, str]:
    log_queue.put(f"   -> Querying NVD for CVSS scores of {len(cve_ids)} CVEs...")
    scores_map = {cve_id: "N/A" for cve_id in cve_ids}
    max_retries = 3

    # --- Attempt 1: Batch request for speed ---
    log_queue.put("      - Attempting fast batch request...")
    try:
        response = requests.get(f"{NVD_API_URL_BASE}{','.join(cve_ids)}", timeout=20)
        if response.status_code == 404: raise requests.exceptions.HTTPError(response=response) # Trigger fallback
        response.raise_for_status()
        data = response.json()
        for vulnerability in data.get('vulnerabilities', []):
            cve_id = vulnerability['cve']['id']
            metrics = vulnerability['cve']['metrics']
            cvss_metrics = metrics.get('cvssMetricV31', [])
            if cvss_metrics:
                metric = cvss_metrics[0]['cvssData']
                scores_map[cve_id] = f"{metric.get('baseScore')} ({metric.get('baseSeverity')})"
            else: scores_map[cve_id] = "CVSS v3.1 N/A"
        log_queue.put("      - Batch request successful.")
        return scores_map
    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code == 404:
            log_queue.put("      - Batch failed with 404. Falling back to individual requests...")
            for cve_id in cve_ids:
                scores_map[cve_id] = get_single_cvss_score(cve_id)
                time.sleep(1) # Rate limit for individual requests
            return scores_map
        # For other HTTP errors, fall through to retry logic
    except requests.exceptions.RequestException:
        pass # Fall through to retry logic

    # --- Attempts 2 & 3: Individual requests for robustness ---
    log_queue.put("      - Batch request failed. Retrying individually...")
    for cve_id in cve_ids:
        for attempt in range(max_retries):
            score = get_single_cvss_score(cve_id)
            if score != "Error":
                scores_map[cve_id] = score
                break # Success for this CVE
            if attempt < max_retries - 1:
                time.sleep(3) # Wait before retrying
        log_queue.put(f"        - Score for {cve_id}: {scores_map[cve_id]}")
        time.sleep(1) # Rate limit between different CVEs
    return scores_map


# --- Report & Chart Generation (No changes in this section) ---
def generate_dashboard_charts(all_cve_reports: List[Dict[str, Any]], log_queue: queue.Queue) -> List[Path]:
    log_queue.put("   -> Generating summary charts...")
    all_techniques = [tech for report in all_cve_reports for tech in report.get('techniques', [])]
    all_cwes = [cwe for report in all_cve_reports for cwe in report.get('cwe', [])]
    chart_files = []
    if all_techniques:
        plt.figure(figsize=(10, 6)); plt.barh(*zip(*Counter(all_techniques).most_common(10)), color='darkred')
        plt.xlabel('Number of Occurrences'); plt.title('Top 10 Most Frequent MITRE ATT&CK Techniques')
        plt.gca().invert_yaxis(); plt.tight_layout(); tech_chart_file = Path("temp_top_techniques.png")
        plt.savefig(tech_chart_file); plt.close(); chart_files.append(tech_chart_file)
    if all_cwes:
        plt.figure(figsize=(10, 6)); plt.barh(*zip(*Counter(all_cwes).most_common(10)), color='darkblue')
        plt.xlabel('Number of Occurrences'); plt.title('Top 10 Most Frequent Weaknesses (CWE)')
        plt.gca().invert_yaxis(); plt.tight_layout(); cwe_chart_file = Path("temp_top_cwes.png")
        plt.savefig(cwe_chart_file); plt.close(); chart_files.append(cwe_chart_file)
    return chart_files

def generate_attack_matrix_image(found_techniques_ids: Set[str], mitre_indexer: MitreDataIndexer, output_filename: Path) -> Optional[Path]:
    tactics_map = {tactic['x_mitre_shortname']: tactic for tactic in mitre_indexer.item_by_internal_id.values() if tactic.get('type') == 'x-mitre-tactic'}
    techniques_by_tactic = defaultdict(list)
    for tech_id in found_techniques_ids:
        tech_data = mitre_indexer.technique_by_external_id.get(tech_id)
        if not tech_data: continue
        for phase in tech_data.get('kill_chain_phases', []):
            techniques_by_tactic[phase['phase_name']].append({'id': tech_id, 'name': tech_data['name']})
    if not techniques_by_tactic: return None
    relevant_tactics = sorted([tactics_map[name] for name in techniques_by_tactic.keys()], key=lambda x: x['name'])
    num_tactics = len(relevant_tactics)
    max_rows = max(len(techs) for techs in techniques_by_tactic.values()) if techniques_by_tactic else 0
    fig, ax = plt.subplots(figsize=(max(15, num_tactics * 2.5), max(8, max_rows * 0.7)))
    ax.set_axis_off()
    for i, tactic in enumerate(relevant_tactics):
        ax.text(i + 0.5, max_rows + 0.2, tactic['name'], ha='center', va='bottom', rotation=45, weight='bold', fontsize=12)
        for j, tech in enumerate(sorted(techniques_by_tactic[tactic['x_mitre_shortname']], key=lambda x: x['id'])):
            rect = patches.Rectangle((i, max_rows - j - 1), 1, 1, linewidth=1, edgecolor='white', facecolor='darkred')
            ax.add_patch(rect)
            ax.text(i + 0.5, max_rows - j - 0.5, tech['id'], ha='center', va='center', fontsize=10, color='white', weight='bold')
    ax.set_xlim(0, num_tactics); ax.set_ylim(-0.5, max_rows + 1); plt.tight_layout(pad=3.0)
    plt.savefig(output_filename, dpi=150); plt.close()
    return output_filename

def draw_footer(canvas, doc):
    canvas.saveState(); canvas.setFont('Helvetica', 9); canvas.setFillColor(colors.red)
    canvas.drawString(doc.leftMargin, doc.bottomMargin - 20, "TLP: RED")
    canvas.setFillColor(colors.black)
    canvas.drawCentredString(doc.width / 2.0 + doc.leftMargin, doc.bottomMargin - 20, "CONFIDENTIAL DOCUMENT")
    canvas.drawRightString(doc.width + doc.leftMargin, doc.bottomMargin - 20, f"Page {doc.page}")
    canvas.restoreState()

def create_pdf_report(all_cve_reports: List[Dict[str, Any]], mitre_indexer: MitreDataIndexer, output_pdf: Path, log_queue: queue.Queue, logo_path: Optional[Path]):
    doc = SimpleDocTemplate(str(output_pdf), pagesize=letter)
    story: List[Any] = []; styles = getSampleStyleSheet(); temp_files_to_clean: Set[Path] = set()
    log_queue.put(f"\n5. Generating optimized PDF report: {output_pdf}...")
    if logo_path and logo_path.exists():
        try:
            story.append(Image(logo_path, width=2*inch, height=1*inch, kind='proportional')); story.append(Spacer(1, 0.5*inch))
        except Exception as e: log_queue.put(f"WARNING: Could not embed logo. Error: {e}")
    story.append(Paragraph("Vulnerability Intelligence Report", styles['h1'])); story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph(f"Vulnerabilities Analyzed: {len(all_cve_reports)}", styles['h2']))
    story.append(Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['BodyText'])); story.append(PageBreak())
    story.append(Paragraph("Executive Summary & Trends", styles['h1']))
    chart_files = generate_dashboard_charts(all_cve_reports, log_queue); temp_files_to_clean.update(chart_files)
    for chart_file in chart_files:
        story.append(Image(chart_file, width=7.5*inch, height=4.5*inch, kind='proportional')); story.append(Spacer(1, 0.3*inch))
    story.append(PageBreak())
    all_techniques_flat = {tech for report in all_cve_reports for tech in report.get('techniques', [])}
    if all_techniques_flat:
        consolidated_matrix_file = Path("temp_consolidated_matrix.png")
        if generate_attack_matrix_image(all_techniques_flat, mitre_indexer, consolidated_matrix_file):
            temp_files_to_clean.add(consolidated_matrix_file)
            story.append(Paragraph("Consolidated MITRE ATT&CK Matrix", styles['h1']))
            story.append(Paragraph("This matrix shows all techniques identified across all analyzed vulnerabilities.", styles['BodyText']))
            story.append(Spacer(1, 0.2*inch)); story.append(Image(consolidated_matrix_file, width=8*inch, height=5.5*inch, kind='proportional')); story.append(PageBreak())
    unique_tech_infos = list({info['id']: info for report in all_cve_reports for info in report.get('techniques_infos', [])}.values())
    actor_intelligence = mitre_indexer.map_techniques_to_actors(unique_tech_infos, log_queue)
    for i, report in enumerate(all_cve_reports):
        cve_id = report['cve_id']
        log_queue.put(f"   -> Adding section for {cve_id} to PDF...")
        story.append(Paragraph(f"Vulnerability Analysis for {cve_id}", styles['h1'])); story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("Vulnerability Summary", styles['h2']))
        story.append(Paragraph(f"<b>CVSS Score (v3.1):</b> {report.get('cvss_score', 'N/A')}", styles['BodyText']))
        if report['cwe']: story.append(Paragraph(f"<b>Weaknesses (CWE):</b> {', '.join(report['cwe'])}", styles['BodyText']))
        if report['capec']: story.append(Paragraph(f"<b>Attack Patterns (CAPEC):</b> {', '.join(report['capec'])}", styles['BodyText']))
        story.append(Spacer(1, 0.2*inch))
        if report['techniques']:
            story.append(Paragraph("Tactical Summary (MITRE ATT&CK)", styles['h2']))
            if report['tactics']:
                story.append(Paragraph(f"<b>Observed Tactics:</b> {', '.join(sorted([t.replace('-', ' ').title() for t in report['tactics']]))}", styles['BodyText']))
            matrix_file = Path(f"temp_matrix_{cve_id}.png")
            if generate_attack_matrix_image(set(report['techniques']), mitre_indexer, matrix_file):
                temp_files_to_clean.add(matrix_file); story.append(Image(matrix_file, width=7.5*inch, height=3.75*inch, kind='proportional'))
            story.append(Paragraph("ATT&CK Technique Details", styles['h2']))
            for info in report['techniques_infos']:
                story.append(Spacer(1, 0.1*inch)); story.append(Paragraph(f"{info['technique_id']}: {info['name']}", styles['h3']))
                story.append(Paragraph(f"<i><b>Summary:</b> {info['short_description']}</i>", styles['BodyText']))
                story.append(Paragraph(f"<b>Source:</b> <link href='{info['url']}' color='blue'>{info['url']}</link>", styles['BodyText']))
            cve_techniques_set = set(report['techniques']); potential_actors_text = []
            for actor, actor_techniques in actor_intelligence.items():
                relevant_techniques = cve_techniques_set.intersection(set(actor_techniques))
                if relevant_techniques:
                    potential_actors_text.append(f"<b>{actor}</b> uses: {', '.join(sorted(list(relevant_techniques)))}")
            if potential_actors_text:
                story.append(Spacer(1, 0.2*inch)); story.append(Paragraph("Potential Threat Actors", styles['h2']))
                for line in potential_actors_text: story.append(Paragraph(line, styles['BodyText']))
        else: story.append(Paragraph("<i>No associated MITRE ATT&CK techniques were found in the database.</i>", styles['BodyText']))
        if i < len(all_cve_reports) - 1: story.append(PageBreak())
    try:
        doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
        log_queue.put(f"\nPDF generated successfully: {output_pdf}")
        try:
            if sys.platform == "win32": os.startfile(output_pdf)
            elif sys.platform == "darwin": subprocess.run(['open', output_pdf])
            else: subprocess.run(['xdg-open', output_pdf])
        except Exception as e: log_queue.put(f"Could not open PDF automatically: {e}")
    except Exception as e: log_queue.put(f"CRITICAL ERROR during PDF construction: {e}")
    finally:
        for temp_file in temp_files_to_clean:
            if temp_file.exists(): temp_file.unlink()
        log_queue.put("Temporary files cleaned up.")

# --- Main Thread Logic ---
def run_report_logic(cve_list: List[str], log_queue: queue.Queue, logo_path: Optional[Path]):
    try:
        if not cve_list:
            log_queue.put("CVE list is empty. Halting script."); return
        log_queue.put(f"1. Processing {len(cve_list)} CVEs.")
        all_cvss_scores = get_cvss_scores_batch(cve_list, log_queue)
        cves_by_year = defaultdict(list)
        for cve_id in cve_list:
            try: cves_by_year[cve_id.split('-')[1]].append(cve_id)
            except IndexError: log_queue.put(f"WARNING: Invalid CVE format ignored: {cve_id}")
        mitre_data = get_mitre_data_with_cache(log_queue)
        if not mitre_data: return
        mitre_indexer = MitreDataIndexer(mitre_data)
        all_cve_reports = []
        log_queue.put("\n4. Processing CVEs by year...")
        for year, cves_in_year in sorted(cves_by_year.items()):
            log_queue.put(f"   -> Year {year}...")
            cve_lines = download_jsonl(CVE_URL_TEMPLATE.format(year=year), log_queue)
            cve_data_map = {}
            if cve_lines:
                for line in cve_lines:
                    try: cve_data_map.update(json.loads(line))
                    except json.JSONDecodeError: continue
            for cve_id in cves_in_year:
                cvss_score = all_cvss_scores.get(cve_id, "N/A")
                cve_data = cve_data_map.get(cve_id)
                if not cve_data:
                    log_queue.put(f"     - ATT&CK data not found for {cve_id} in year {year} database.")
                    all_cve_reports.append({"cve_id": cve_id, "cwe": [], "capec": [], "techniques": [], "techniques_infos": [], "tactics": set(), "cvss_score": cvss_score})
                    continue
                techniques = sorted([f"T{t}" if not str(t).startswith("T") else str(t) for t in cve_data.get('TECHNIQUES', [])])
                techniques_infos = [info for t_id in techniques if (info := mitre_indexer.get_technique_info(t_id)) is not None]
                tactics = {phase['phase_name'] for info in techniques_infos for phase in info['kill_chain_phases']}
                all_cve_reports.append({
                    "cve_id": cve_id, "cwe": cve_data.get('CWE', []), "capec": cve_data.get('CAPEC', []),
                    "techniques": techniques, "techniques_infos": techniques_infos, "tactics": tactics, "cvss_score": cvss_score
                })
                log_queue.put(f"     - ATT&CK data extracted for {cve_id}")
        if all_cve_reports:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = Path(f"IntelligenceReport_{timestamp}.pdf")
            create_pdf_report(all_cve_reports, mitre_indexer, output_filename, log_queue, logo_path)
        else: log_queue.put("\nNo vulnerability data could be processed. No report generated.")
    except Exception as e: log_queue.put(f"\nAN UNEXPECTED ERROR OCCURRED: {e}")
    finally: log_queue.put("PROCESS_COMPLETE")

# --- GUI Class ---
class App:
    def __init__(self, root: tk.Tk):
        self.root = root; self.root.title("Vulnerability Intelligence Report Generator"); self.root.geometry("800x450")
        self.cve_list: List[str] = []; self.logo_filepath: Optional[Path] = None
        main_frame = Frame(root, padx=10, pady=10); main_frame.pack(fill=tk.BOTH, expand=True)
        file_frame = Frame(main_frame, pady=10); file_frame.pack(fill=tk.X)
        load_cve_button = Button(file_frame, text="Load CVE File (.txt)", command=self.load_cve_file, font=("Helvetica", 11, "bold"))
        load_cve_button.pack(side=tk.LEFT, padx=(0, 10))
        self.cve_file_label = Label(file_frame, text="No CVE file selected", font=("Helvetica", 10), fg="grey")
        self.cve_file_label.pack(side=tk.LEFT)
        logo_frame = Frame(main_frame, pady=5); logo_frame.pack(fill=tk.X)
        upload_logo_button = Button(logo_frame, text="Upload Logo (Optional)", command=self.upload_logo, font=("Helvetica", 11))
        upload_logo_button.pack(side=tk.LEFT, padx=(0, 10))
        self.logo_file_label = Label(logo_frame, text="No logo selected", font=("Helvetica", 10), fg="grey")
        self.logo_file_label.pack(side=tk.LEFT)
        self.generate_button = Button(main_frame, text="Generate Report", command=self.start_generation, font=("Helvetica", 12, "bold"), bg="#4CAF50", fg="white", state="disabled")
        self.generate_button.pack(pady=10, fill=tk.X, ipady=5)
        Label(main_frame, text="Activity Log:", font=("Helvetica", 12)).pack(anchor='w')
        self.log_output = scrolledtext.ScrolledText(main_frame, height=10, width=90, state='disabled', bg="#f0f0f0", font=("Courier New", 9))
        self.log_output.pack(pady=5, fill=tk.BOTH, expand=True)
        self.log_queue = queue.Queue()
        self.process_log_queue()

    def load_cve_file(self):
        filepath_str = filedialog.askopenfilename(title="Select a CVE file", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not filepath_str: return
        filepath = Path(filepath_str)
        try:
            with open(filepath, 'r', encoding='utf-8') as f: self.cve_list = [line.strip().upper() for line in f if line.strip()]
            if self.cve_list:
                self.cve_file_label.config(text=f"{filepath.name} ({len(self.cve_list)} CVEs)", fg="green")
                self.generate_button.config(state="normal"); self.log_message(f"File '{filepath.name}' loaded successfully.")
            else: self.cve_file_label.config(text="Selected file is empty.", fg="red"); self.generate_button.config(state="disabled")
        except Exception as e: self.cve_file_label.config(text="Error reading file.", fg="red"); self.log_message(f"Error reading file: {e}")

    def upload_logo(self):
        filepath_str = filedialog.askopenfilename(title="Select a Logo Image", filetypes=[("Image Files", "*.png *.jpg *.jpeg"), ("All Files", "*.*")])
        if not filepath_str: self.logo_filepath = None; self.logo_file_label.config(text="No logo selected", fg="grey"); return
        self.logo_filepath = Path(filepath_str)
        self.logo_file_label.config(text=f"Logo: {self.logo_filepath.name}", fg="blue")
        self.log_message(f"Logo '{self.logo_filepath.name}' selected.")
        
    def log_message(self, message: str):
        self.log_output.config(state='normal'); self.log_output.insert(tk.END, message + '\n')
        self.log_output.see(tk.END); self.log_output.config(state='disabled')

    def process_log_queue(self):
        try:
            message = self.log_queue.get_nowait()
            if message == "PROCESS_COMPLETE": self.generate_button.config(state="normal", text="Generate Report")
            else: self.log_message(message)
        except queue.Empty: pass
        finally: self.root.after(100, self.process_log_queue)

    def start_generation(self):
        if not self.cve_list: self.log_message("Error: No CVE list has been loaded."); return
        self.log_output.config(state='normal'); self.log_output.delete('1.0', tk.END); self.log_output.config(state='disabled')
        self.generate_button.config(state="disabled", text="Generating Report...")
        thread = threading.Thread(target=run_report_logic, args=(self.cve_list, self.log_queue, self.logo_filepath))
        thread.daemon = True; thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
