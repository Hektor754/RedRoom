# RedRoom Toolkit – CLI Usage Documentation

## What is the RedRoom?

---

RedRoom is the core idea behind my thesis: a unified tool that combines recon, vulnerability assessment, and exploitation into one framework.  
The goal is to simulate the workflow a hacker or penetration tester typically follows when attempting to compromise a system.

Everything in RedRoom is implemented from scratch for educational purposes — meaning no external recon scanners, exploit kits, or vulnerability‑scanning tools are used internally. Each step of the hacking methodology has its own modules inside the toolkit.

---

### Reconnaissance Module
- Host scanning  
- Host profiling  
- Port scanning  
- Traceroute  
- DNS enumeration  
- Subdomain enumeration  

### Vulnerability Analysis Module
- CVE lookup  
- Service misconfiguration checking  
- Web scanner  

### Exploitation Module
- DoS simulator  
- Phishing email simulation  
- SQL injection framework  

---

The architecture is structured so that the main program reads user‑provided arguments, then delegates execution to the selected tool’s handler inside the appropriate “stage” folder.  
Each handler calls the internal methods it needs, with those methods organized inside subfolders under each stage.

This design allows the user to either:
- follow the full workflow in the correct order (recon → analysis → exploitation), **or**
- run any tool as a standalone, depending on what they need.

---

### DISCLAIMER  
This toolkit contains features that can be harmful if misused.  
Do not run it against any system unless you have explicit authorization.  
It is intended strictly for learning, experimentation, and academic purposes.

---

## How to Run Each Tool

Inside the `Essentials` folder, you will find `command_center`, which lists every valid combination of modules, tools, and flags available in RedRoom.

The general command format is:
```
sudo python3 -m main -c <category> -t <tool> [OPTIONS]
```

This structure applies to all tools regardless of the stage they belong to.