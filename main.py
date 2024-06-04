import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import threading
from src.analyzer import analyze_pcap  # Ensure this is the correct import path

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("VoIP SIP Analysis Tool")
        self.root.geometry("800x500")
        self.root.configure(bg='#f0f0f0')

        # Set custom font
        self.customFont = ('Arial', 12)

        # Initialize UI components
        self.create_widgets()

    def create_widgets(self):
        # Upper frame for description and file selection
        upper_frame = tk.Frame(self.root, bg='#f0f0f0')
        upper_frame.pack(padx=10, pady=10, fill='x')

        tk.Label(upper_frame, text="Describe the problem (optional):", font=self.customFont, bg='#f0f0f0').pack(anchor='w')
        self.desc_text = scrolledtext.ScrolledText(upper_frame, height=4, width=90, font=self.customFont)
        self.desc_text.pack(padx=5, pady=5, fill='x')

        file_frame = tk.Frame(upper_frame, bg='#f0f0f0')
        file_frame.pack(fill='x', pady=10)
        tk.Label(file_frame, text="Select a PCAP file:", font=self.customFont, bg='#f0f0f0').pack(side='left')
        self.file_path_entry = tk.Entry(file_frame, width=50, state='disabled', font=self.customFont)
        self.file_path_entry.pack(side='left', padx=5)
        tk.Button(file_frame, text="Browse", command=self.browse_file, font=self.customFont).pack(side='right')

        # Progress label
        self.progress_label = tk.Label(self.root, text="", bg='#f0f0f0', font=self.customFont)
        self.progress_label.pack(pady=5)

        # Analyze button
        tk.Button(self.root, text="Analyze", command=self.start_analysis, font=self.customFont, bg='#4CAF50', fg='white').pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select a PCAP file", filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            self.file_path_entry.configure(state='normal')
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)
            self.file_path_entry.configure(state='disabled')

    def start_analysis(self):
        file_path = self.file_path_entry.get()
        if not file_path.strip():
            messagebox.showwarning("Warning", "Please select a PCAP file.")
            return
        
        self.progress_label.config(text="Analyzing... Please wait.")
        
        analysis_thread = threading.Thread(target=self.analyze, args=(file_path,))
        analysis_thread.start()

    def analyze(self, file_path):
        try:
            analysis_results = analyze_pcap(file_path)
            self.root.after(0, self.show_results, analysis_results)
            self.root.after(0, self.progress_label.config, {"text": "Analysis complete."})
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"Failed to analyze PCAP file: {str(e)}")
            self.root.after(0, self.progress_label.config, {"text": ""})

    def show_results(self, analysis_results):
        results_window = tk.Toplevel(self.root)
        results_window.title("Analysis Results")
        results_window.geometry("800x600")

        text_area = scrolledtext.ScrolledText(results_window, wrap=tk.WORD, font=('TkFixedFont', 10))
        text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for result in analysis_results:
            text_area.insert(tk.END, f"Call ID: {result['Call ID']}\n")
            text_area.insert(tk.END, f"Originating IP: {result['Originating IP']}\n")
            text_area.insert(tk.END, f"Destination IP: {result['Destination IP']}\n")
            text_area.insert(tk.END, f"Caller: {result['Caller']}\n")
            text_area.insert(tk.END, f"Called Party: {result['Called Party']}\n")
            text_area.insert(tk.END, "Call Flow:\n")
            for event in result["Call Flow"]:
                text_area.insert(tk.END, f"  - {event}\n")
            if result["Errors"]:
                text_area.insert(tk.END, "Issues Detected:\n")
                for error in result["Errors"]:
                    text_area.insert(tk.END, f"  - {error}\n")
            text_area.insert(tk.END, "Call Summary:\n")
            for key, value in result["Summary"].items():
                text_area.insert(tk.END, f"  {key}: {value}\n")
            text_area.insert(tk.END, "IP Details:\n")
            for ip, details in result["IP Details"].items():
                text_area.insert(tk.END, f"  IP: {ip}, Role: {details['role']}\n")
            for action in details["actions"]:
                text_area.insert(tk.END, f"    - {action}\n")
            text_area.insert(tk.END, "\n\n")
        text_area.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
