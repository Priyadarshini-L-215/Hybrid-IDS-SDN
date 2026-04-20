import nmap
try:
    search_paths = ('nmap', 'nmap.exe', r'C:\Program Files (x86)\Nmap\nmap.exe', r'C:\Program Files\Nmap\nmap.exe')
    nm = nmap.PortScanner(nmap_search_path=search_paths)
    print("Found nmap:", nm.nmap_version())
except Exception as e:
    print("Error:", e)
