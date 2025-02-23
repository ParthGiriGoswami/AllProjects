import psutil
import os
import yara
import notifypy
files = set()
flag = False  
def list_connected_devices():
    global flag
    devices = []
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if 'removable' in partition.opts or partition.fstype in ['vfat', 'exfat', 'ntfs']:
            devices.append(partition.device)
    if devices and not flag:
        flag = True
        scan_devices(devices)
        notify_results()
    elif not devices and flag:
        flag = False
def scan_devices(devices):
    rule = """
        rule ExampleMalware
        {
            strings:
                $ransomware_pattern = {50 53 51 52 56 57 55 41 54 41 55 41 56 41 57}
                $keylogger_pattern = {6A 00 68 00 30 00 00 64 FF 35 30 00 00 00}
                $suspicious_cmd = "cmd.exe /c"
                $powershell_script = "powershell.exe -nop -w hidden"
                $shellcode_pattern = {31 C0 50 68 2E 65 78 65 68 63 61 6C 63 54 5F 50 57 56 50 FF D0}
            condition:
                any of ($ransomware_pattern, $keylogger_pattern, $suspicious_cmd, $powershell_script, $shellcode_pattern)
        }
    """
    compiled_rule = yara.compile(source=rule)
    for device in devices:
        try:
            with os.scandir(device) as entries:
                for entry in entries:
                    if entry.is_file():
                        matches = compiled_rule.match(entry.path)
                        if matches:
                            files.add(entry.path)
                    elif entry.is_dir(follow_symlinks=False):
                        scan_devices([entry.path])  
        except:
            pass
def notify_results():
    if os.name == "nt":  
        icon_path = os.path.abspath("icon.ico")
    else:
        icon_path = os.path.abspath("icon.png")
    if not os.path.exists(icon_path):
        icon_path = None
    if len(files) == 0:
        notification = notifypy.Notify() 
        notification.application_name = "Kepler Antivirus"
        notification.title = "Information"
        notification.message ="No malware found!"
        notification.urgency = "critical"
        notification.icon = icon_path
        notification.send(block=False)
    else:
        notification = notifypy.Notify() 
        notification.application_name = "Kepler Antivirus"
        notification.title = "Information"
        notification.message =f"{len(files)} malware files found!",
        notification.urgency = "critical"
        notification.icon = icon_path
        notification.send(block=False)