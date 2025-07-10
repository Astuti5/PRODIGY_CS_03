# Password checker
import tkinter as tk
from tkinter import ttk
import re
def check_password_strength(password):
    # Checks if password meets basic security rules
    results = {
        "long_enough": len(password) >= 8,
        "not_too_long": len(password) <= 64,
        "has_uppercase": bool(re.search(r'[A-Z]', password)),
        "has_lowercase": bool(re.search(r'[a-z]', password)),
        "has_number": bool(re.search(r'[0-9]', password)),
        "has_special": bool(re.search(r'[^a-z0-9\s]', password, re.I)),
        "not_dumb": True  # Default to True
    }
    # Common bad passwords
    bad_ones = ["password", "123456", "qwerty", "letmein"]
    pw_lower = password.lower()
    
    if any(bad in pw_lower for bad in bad_ones):
        results["not_dumb"] = False
    elif re.search(r'(.)\1{2,}', pw_lower): 
        results["not_dumb"] = False
    
    # Check for sequences like abc, 123
    for i in range(len(password) - 2):
        if (ord(pw_lower[i]) + 1 == ord(pw_lower[i+1]) and
            ord(pw_lower[i+1]) + 1 == ord(pw_lower[i+2])):
            results["not_dumb"] = False
            break
    
    return results

class PasswordChecker:
    def __init__(self, window):
        window.title("Password Strength Checker")
        window.geometry("400x450")  
        window.resizable(0, 0)
        
        # Main container
        main_frame = ttk.Frame(window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=1)
        
        pw_frame = ttk.Frame(main_frame)
        pw_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(pw_frame, text="Your password:").pack(side=tk.LEFT)
      
        self.show_password = False
        self.eye_btn = ttk.Button(
            pw_frame,
            text="👁",  
            width=3,
            command=self.toggle_visibility
        )
        self.eye_btn.pack(side=tk.RIGHT)
        
        # Actual password entry
        self.pw_entry = ttk.Entry(main_frame, show="•", width=30)
        self.pw_entry.pack(fill=tk.X)
        self.pw_entry.bind("<KeyRelease>", self.check_pw)
        
        # Strength display
        self.strength_text = ttk.Label(
            main_frame,
            text="Strength: Not checked yet",
            font=("Helvetica", 12, "bold")
        )
        self.strength_text.pack(pady=10)
        
        # Requirements box
        req_box = ttk.LabelFrame(main_frame, text="Must have:", padding=10)
        req_box.pack(fill=tk.BOTH, expand=1)
        
        
        self.rules = {
            "long_enough": ttk.Label(req_box, text="✘ At least 8 chars"),
            "not_too_long": ttk.Label(req_box, text="✘ Under 65 chars"), 
            "has_uppercase": ttk.Label(req_box, text="✘ Capital letter"),
            "has_lowercase": ttk.Label(req_box, text="✘ Lowercase letter"),
            "has_number": ttk.Label(req_box, text="✘ Number"),
            "has_special": ttk.Label(req_box, text="✘ Special character"),
            "not_dumb": ttk.Label(req_box, text="✘ Not obvious pattern")
        }
        
        for rule in self.rules.values():
            rule.pack(anchor=tk.W, pady=2)
        
        self.check_pw()  # Initial check
    
    def toggle_visibility(self):
        # Toggle between showing password and hiding it
        self.show_password = not self.show_password
        if self.show_password:
            self.pw_entry.config(show="")
            self.eye_btn.config(text="🔒")
        else:
            self.pw_entry.config(show="•")
            self.eye_btn.config(text="👁")
    
    def check_pw(self, event=None):
        pw = self.pw_entry.get()
        checks = check_password_strength(pw)
        
        # Update rule checks
        passed = 0
        for rule, label in self.rules.items():
            if checks[rule]:
                label.config(text=f"✔ {label.cget('text')[2:]}")
                passed += 1
            else:
                label.config(text=f"✘ {label.cget('text')[2:]}")
        
        # Update strength text
        if not pw:
            self.strength_text.config(text="Strength: Not checked yet")
        elif passed == len(checks):
            self.strength_text.config(text="Strength: Perfect!", foreground="green")
        elif passed >= len(checks)-2:
            self.strength_text.config(text="Strength: Decent", foreground="blue")
        else:
            self.strength_text.config(text="Strength: Weak", foreground="red")

if __name__ == "__main__":
    root = tk.Tk()
    PasswordChecker(root)
    root.mainloop()
