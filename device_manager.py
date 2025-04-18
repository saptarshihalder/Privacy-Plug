import time
import subprocess
import sys
import os
import json
import paho.mqtt.client as paho
from paho import mqtt
import winreg
import ctypes
import platform
import ssl
import traceback
from datetime import datetime

# Check if running with admin privileges and restart with admin rights if needed
def ensure_admin():
    if platform.system() != 'Windows':
        print("This script is designed for Windows only.")
        sys.exit(1)
        
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"Error checking admin status: {e}")
        is_admin = False
        
    if not is_admin:
        print("Requesting administrator privileges...")
        # Re-run the program with admin rights
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                " ".join(['"' + sys.argv[0] + '"'] + sys.argv[1:]), 
                None, 
                1  # SW_SHOWNORMAL
            )
            sys.exit(0)
        except Exception as e:
            print(f"Failed to restart with admin privileges: {e}")
            sys.exit(1)
    
    print("Running with administrator privileges.")
    return True

# ===== HiveMQ Cloud Configuration =====
MQTT_BROKER = "34907036e79f49899c46b6fec77e7f23.s1.eu.hivemq.cloud"
MQTT_PORT = 8883  # TLS port
MQTT_USERNAME = "RFID_1"
MQTT_PASSWORD = "RFID_rfid_1"

device_id = "device1"
topic_subscribe = f"esp32/disable/{device_id}"
enable_topic_subscribe = f"esp32/enable/{device_id}"
rfid_topic = "esp32/rfid/scan"
target_rfid_enable_tag = "e1c83102"  # Special RFID tag that enables permissions
target_rfid_disable_tag = "e2c95304"  # Special RFID tag that disables permissions and closes apps

# Keep track of disabled permissions for re-enabling
disabled_permissions_history = {
    "timestamp": "",
    "permissions": []
}

# ===== Application Management Functions =====
def detect_camera_apps():
    """
    Detects applications currently using the camera
    Returns a list of process IDs
    """
    print("Detecting applications using camera...")
    camera_apps = []
    
    try:
        # Use PowerShell to detect processes with camera access
        # This PowerShell command gets processes that have open handles to camera devices
        ps_cmd = r'powershell -Command "Get-Process | Where-Object {$_.Modules.ModuleName -contains \"avicap32.dll\" -or $_.Modules.ModuleName -contains \"mf.dll\"} | Select-Object -Property Name, Id | ConvertTo-Json"'
        
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                # Parse the JSON output from PowerShell
                processes = json.loads(result.stdout)
                
                # Handle case where only one process is returned (not in a list)
                if isinstance(processes, dict):
                    processes = [processes]
                
                for process in processes:
                    camera_apps.append({
                        "name": process.get("Name", "Unknown"),
                        "pid": process.get("Id", 0)
                    })
                    print(f"Detected camera app: {process.get('Name')} (PID: {process.get('Id')})")
            except json.JSONDecodeError:
                print("Error parsing process list")
    except Exception as e:
        print(f"Error detecting camera apps: {e}")
    
    # Fallback method if the first approach didn't find anything
    if not camera_apps:
        try:
            # Check for common camera apps by name
            common_camera_apps = [
                "zoom.exe", "teams.exe", "skype.exe", "webex.exe", 
                "discord.exe", "slack.exe", "chrome.exe", "msedge.exe",
                "firefox.exe", "camera.exe", "microsoft.windows.camera"
            ]
            
            ps_cmd = r'powershell -Command "Get-Process | Where-Object {$_.Name -match \'' + '|'.join(common_camera_apps) + r'\'} | Select-Object -Property Name, Id | ConvertTo-Json"'
            
            result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    processes = json.loads(result.stdout)
                    
                    # Handle case where only one process is returned
                    if isinstance(processes, dict):
                        processes = [processes]
                    
                    for process in processes:
                        camera_apps.append({
                            "name": process.get("Name", "Unknown"),
                            "pid": process.get("Id", 0)
                        })
                        print(f"Detected potential camera app: {process.get('Name')} (PID: {process.get('Id')})")
                except json.JSONDecodeError:
                    print("Error parsing process list")
        except Exception as e:
            print(f"Error with fallback camera detection: {e}")
    
    return camera_apps

def detect_microphone_apps():
    """
    Detects applications currently using the microphone
    Returns a list of process IDs
    """
    print("Detecting applications using microphone...")
    mic_apps = []
    
    try:
        # Use PowerShell to detect processes with microphone access
        ps_cmd = r'powershell -Command "Get-Process | Where-Object {$_.Modules.ModuleName -contains \"audioses.dll\" -or $_.Modules.ModuleName -contains \"audioeng.dll\"} | Select-Object -Property Name, Id | ConvertTo-Json"'
        
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                # Parse the JSON output from PowerShell
                processes = json.loads(result.stdout)
                
                # Handle case where only one process is returned
                if isinstance(processes, dict):
                    processes = [processes]
                
                for process in processes:
                    mic_apps.append({
                        "name": process.get("Name", "Unknown"),
                        "pid": process.get("Id", 0)
                    })
                    print(f"Detected microphone app: {process.get('Name')} (PID: {process.get('Id')})")
            except json.JSONDecodeError:
                print("Error parsing process list")
    except Exception as e:
        print(f"Error detecting microphone apps: {e}")
    
    # Fallback method if the first approach didn't find anything
    if not mic_apps:
        try:
            # Check for common microphone apps by name
            common_mic_apps = [
                "zoom.exe", "teams.exe", "skype.exe", "webex.exe", 
                "discord.exe", "slack.exe", "chrome.exe", "msedge.exe",
                "firefox.exe", "voicerecorder.exe"
            ]
            
            ps_cmd = r'powershell -Command "Get-Process | Where-Object {$_.Name -match \'' + '|'.join(common_mic_apps) + r'\'} | Select-Object -Property Name, Id | ConvertTo-Json"'
            
            result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    processes = json.loads(result.stdout)
                    
                    # Handle case where only one process is returned
                    if isinstance(processes, dict):
                        processes = [processes]
                    
                    for process in processes:
                        mic_apps.append({
                            "name": process.get("Name", "Unknown"),
                            "pid": process.get("Id", 0)
                        })
                        print(f"Detected potential microphone app: {process.get('Name')} (PID: {process.get('Id')})")
                except json.JSONDecodeError:
                    print("Error parsing process list")
        except Exception as e:
            print(f"Error with fallback microphone detection: {e}")
    
    return mic_apps

def terminate_app(pid, name):
    """
    Terminates an application by its process ID
    Returns True if successful, False otherwise
    """
    try:
        print(f"Terminating {name} (PID: {pid})...")
        
        # Use taskkill to terminate the process
        cmd = f'taskkill /F /PID {pid}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Successfully terminated {name}")
            return True
        else:
            print(f"Failed to terminate {name}: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error terminating {name}: {e}")
        return False

def terminate_invasive_apps():
    """
    Detects and terminates applications using camera and microphone
    Returns a summary of terminated applications
    """
    print("\n=== Terminating Invasive Applications ===")
    results = {
        "camera_apps": [],
        "microphone_apps": [],
        "terminated_count": 0,
        "failed_count": 0
    }
    
    # Detect camera apps
    camera_apps = detect_camera_apps()
    results["camera_apps"] = camera_apps
    
    # Detect microphone apps
    mic_apps = detect_microphone_apps()
    results["microphone_apps"] = mic_apps
    
    # Terminate detected applications
    termination_results = []
    
    print("\n--- Terminating Camera Applications ---")
    for app in camera_apps:
        pid = app.get("pid")
        name = app.get("name")
        if pid and name:
            success = terminate_app(pid, name)
            termination_results.append({
                "name": name,
                "pid": pid,
                "type": "camera",
                "success": success
            })
            if success:
                results["terminated_count"] += 1
            else:
                results["failed_count"] += 1
    
    print("\n--- Terminating Microphone Applications ---")
    for app in mic_apps:
        pid = app.get("pid")
        name = app.get("name")
        if pid and name:
            # Skip if this app was already terminated (might be in both lists)
            if not any(r["pid"] == pid for r in termination_results):
                success = terminate_app(pid, name)
                termination_results.append({
                    "name": name,
                    "pid": pid,
                    "type": "microphone",
                    "success": success
                })
                if success:
                    results["terminated_count"] += 1
                else:
                    results["failed_count"] += 1
    
    print(f"\nTerminated {results['terminated_count']} applications, failed to terminate {results['failed_count']} applications")
    results["termination_results"] = termination_results
    
    return results

# ===== Permission Categories and Keywords =====
PERMISSION_CATEGORIES = {
    "Camera Access": {
        "keywords": ["camera", "video", "webcam", "capture", "photo", "imaging"],
        "check": lambda: check_permission("camera"),
        "disable": lambda: disable_permission("camera"),
        "enable": lambda: enable_permission("camera")
    },
    "Location Tracking": {
        "keywords": ["location", "gps", "tracking", "geo", "map", "position"],
        "check": lambda: check_permission("location"),
        "disable": lambda: disable_permission("location"),
        "enable": lambda: enable_permission("location")
    },
    "Storage Access": {
        "keywords": ["storage", "usb", "drive", "disk", "backup", "file", "data"],
        "check": lambda: check_storage_access(),
        "disable": lambda: disable_storage(),
        "enable": lambda: enable_storage()
    },
    "Microphone Access": {
        "keywords": ["microphone", "mic", "audio", "recording", "sound", "voice"],
        "check": lambda: check_permission("microphone"),
        "disable": lambda: disable_permission("microphone"),
        "enable": lambda: enable_permission("microphone")
    },
    "Background Apps": {
        "keywords": ["background", "telemetry", "tracking", "monitor", "process"],
        "check": lambda: check_background_apps(),
        "disable": lambda: disable_background_apps(),
        "enable": lambda: enable_background_apps()
    },
    "Notification Access": {
        "keywords": ["notification", "alert", "toast", "message"],
        "check": lambda: check_permission("userNotificationListener"),
        "disable": lambda: disable_permission("userNotificationListener"),
        "enable": lambda: enable_permission("userNotificationListener")
    },
    "Contacts Access": {
        "keywords": ["contacts", "address", "people", "phone", "email", "friend"],
        "check": lambda: check_permission("contacts"),
        "disable": lambda: disable_permission("contacts"),
        "enable": lambda: enable_permission("contacts")
    }
}

# ===== Callback functions =====
def on_connect(client, userdata, flags, rc, properties=None):
    """Callback for when the client receives a CONNACK response from the server."""
    if rc == 0:
        print(f"Connected successfully to {MQTT_BROKER}")
        # Subscribe with error handling
        try:
            # Subscribe to the disable topic
            result, mid = client.subscribe(topic_subscribe, qos=1)
            if result == 0:
                print(f"Subscribed to topic: {topic_subscribe}")
            else:
                print(f"Failed to subscribe to topic: {topic_subscribe}, result code: {result}")
                
            # Subscribe to the enable topic
            result, mid = client.subscribe(enable_topic_subscribe, qos=1)
            if result == 0:
                print(f"Subscribed to topic: {enable_topic_subscribe}")
            else:
                print(f"Failed to subscribe to topic: {enable_topic_subscribe}, result code: {result}")
                
            # Subscribe to RFID scan topic
            result, mid = client.subscribe(rfid_topic, qos=1)
            if result == 0:
                print(f"Subscribed to RFID scan topic: {rfid_topic}")
            else:
                print(f"Failed to subscribe to RFID scan topic: {rfid_topic}, result code: {result}")
                
        except Exception as e:
            print(f"Exception during subscribe: {e}")
    else:
        print(f"Failed to connect, return code: {rc}")
        # Connection return codes:
        # 0: Connection successful
        # 1: Connection refused - incorrect protocol version
        # 2: Connection refused - invalid client identifier
        # 3: Connection refused - server unavailable
        # 4: Connection refused - bad username or password
        # 5: Connection refused - not authorized

def on_disconnect(client, userdata, rc, properties=None):
    """Callback for when the client disconnects from the server."""
    print(f"Disconnected with result code: {rc}")
    if rc != 0:
        print("Unexpected disconnection. Attempting to reconnect...")
        try_reconnect(client)

def try_reconnect(client, max_retries=10):
    """Try to reconnect to the MQTT broker with exponential backoff."""
    retries = 0
    while retries < max_retries:
        try:
            print(f"Attempting to reconnect... (Attempt {retries+1}/{max_retries})")
            client.reconnect()
            return True
        except Exception as e:
            print(f"Reconnection failed: {e}")
            retries += 1
            time.sleep(min(2**retries, 60))  # Exponential backoff
    print("Max reconnection attempts reached. Exiting.")
    return False

def on_publish(client, userdata, mid, properties=None):
    """Callback for when a message has been published."""
    print(f"Published message, mid: {mid}")

def on_subscribe(client, userdata, mid, granted_qos, properties=None):
    """Callback for when the client subscribes to a topic."""
    if isinstance(granted_qos, list):
        qos_str = ", ".join(str(q) for q in granted_qos)
    else:
        qos_str = str(granted_qos)
    print(f"Subscription acknowledged. mid: {mid}, granted QoS: {qos_str}")

def on_message(client, userdata, msg):
    """Callback for when a message is received from the server."""
    try:
        payload = msg.payload.decode().strip()
        print(f"\n=== Message received on topic '{msg.topic}': {payload} ===")
        
        # Handle RFID scan events
        if msg.topic == rfid_topic:
            handle_rfid_scan(client, payload)
            return
        
        # Handle disable permissions requests
        if msg.topic == topic_subscribe:
            if payload == "disable_permissions":
                # First terminate any invasive applications
                print("\nClosing applications that use camera and microphone...")
                termination_results = terminate_invasive_apps()
                
                # Then disable all permissions
                disabled_results = disable_all_permissions()
                
                # Format results for display and MQTT
                status_msg = {
                    "timestamp": get_timestamp(),
                    "disabled_permissions": [],
                    "failed_permissions": [],
                    "terminated_apps": {
                        "camera": [app["name"] for app in termination_results["camera_apps"]],
                        "microphone": [app["name"] for app in termination_results["microphone_apps"]],
                        "terminated_count": termination_results["terminated_count"],
                        "failed_count": termination_results["failed_count"]
                    }
                }
                
                print("\n=== PERMISSION DISABLE RESULTS ===")
                for perm, success in disabled_results.items():
                    status = "✓ SUCCESS" if success else "✗ FAILED"
                    print(f"{perm}: {status}")
                    if success:
                        status_msg["disabled_permissions"].append(perm)
                    else:
                        status_msg["failed_permissions"].append(perm)
                
                overall_success = all(disabled_results.values())
                status_msg["overall_success"] = overall_success
                status = "permissions_disabled" if overall_success else "permissions_disable_partial"
                
                # Publish results
                client.publish(f"esp32/status/{device_id}", status, qos=1)
                client.publish(f"esp32/permissions_result/{device_id}", json.dumps(status_msg), qos=1)
                
            elif payload == "list_software":
                # Get all installed software
                software_list = get_installed_software(display_local=True)
                
                # Create categories for better organization
                categories = categorize_software(software_list)
                
                # Create report
                report = {
                    "timestamp": get_timestamp(),
                    "total_software": len(software_list),
                    "software_by_category": categories,
                    "all_software": software_list
                }
                
                # Publish software list
                client.publish(f"esp32/software/{device_id}", json.dumps(report), qos=1)
                print(f"Published list of {len(software_list)} installed software packages to MQTT")
                
            elif payload == "scan_and_disable_invasive":
                # Run the comprehensive scan
                scan_results = scan_software_and_permissions(client, disable_mode=True)
                
                # Results are already published by the scan function
                print("\n=== Scan and disable operation completed ===")
                
            elif payload == "scan_only":
                # Scan software but don't disable anything
                scan_results = scan_software_and_permissions(client, disable_mode=False)
                
                # Results are already published by the scan function
                print("\n=== Scan-only operation completed ===")
                
            elif payload == "system_info":
                # Get and publish system information
                system_info = get_system_info()
                client.publish(f"esp32/system_info/{device_id}", json.dumps(system_info), qos=1)
                
                # Display locally
                print("\n=== SYSTEM INFORMATION ===")
                for key, value in system_info.items():
                    print(f"{key}: {value}")
                
            else:
                print(f"Unknown command on disable topic: {payload}")
                client.publish(f"esp32/unknown_command/{device_id}", payload, qos=1)
        
        # Handle enable permissions requests
        elif msg.topic == enable_topic_subscribe:
            if payload == "enable_permissions":
                # Enable all permissions
                enabled_results = enable_all_permissions()
                
                # Format results for display and MQTT
                status_msg = {"timestamp": get_timestamp()}
                status_msg["enabled_permissions"] = []
                status_msg["failed_permissions"] = []
                
                print("\n=== PERMISSION ENABLE RESULTS ===")
                for perm, success in enabled_results.items():
                    status = "✓ SUCCESS" if success else "✗ FAILED"
                    print(f"{perm}: {status}")
                    if success:
                        status_msg["enabled_permissions"].append(perm)
                    else:
                        status_msg["failed_permissions"].append(perm)
                
                overall_success = any(enabled_results.values())
                status_msg["overall_success"] = overall_success
                status = "permissions_enabled" if overall_success else "permissions_enable_failed"
                
                # Publish results
                client.publish(f"esp32/status/{device_id}", status, qos=1)
                client.publish(f"esp32/permissions_result/{device_id}", json.dumps(status_msg), qos=1)
            
            elif payload == "enable_disabled_permissions":
                # Enable only permissions that were previously disabled
                enabled_results = enable_disabled_permissions()
                
                # Format results for display and MQTT
                status_msg = {"timestamp": get_timestamp()}
                status_msg["enabled_permissions"] = []
                status_msg["failed_permissions"] = []
                
                print("\n=== PERMISSION ENABLE RESULTS (PREVIOUSLY DISABLED) ===")
                for perm, success in enabled_results.items():
                    status = "✓ SUCCESS" if success else "✗ FAILED"
                    print(f"{perm}: {status}")
                    if success:
                        status_msg["enabled_permissions"].append(perm)
                    else:
                        status_msg["failed_permissions"].append(perm)
                
                overall_success = any(enabled_results.values())
                status_msg["overall_success"] = overall_success
                status = "permissions_enabled" if overall_success else "permissions_enable_failed"
                
                # Publish results
                client.publish(f"esp32/status/{device_id}", status, qos=1)
                client.publish(f"esp32/permissions_result/{device_id}", json.dumps(status_msg), qos=1)
            
            else:
                print(f"Unknown command on enable topic: {payload}")
                client.publish(f"esp32/unknown_command/{device_id}", payload, qos=1)
                
    except Exception as e:
        error_details = {
            "timestamp": get_timestamp(),
            "error": str(e),
            "traceback": traceback.format_exc()
        }
        print(f"Error processing message: {e}")
        print(traceback.format_exc())
        client.publish(f"esp32/error/{device_id}", json.dumps(error_details), qos=1)

def handle_rfid_scan(client, rfid_id):
    """Handle RFID scan events"""
    print(f"\n=== RFID Scan Detected: {rfid_id} ===")
    
    # Check if this is the special RFID tag that enables permissions
    if rfid_id == target_rfid_enable_tag:
        print(f"Detected special RFID tag {target_rfid_enable_tag} - enabling permissions")
        
        # Enable previously disabled permissions
        enabled_results = enable_disabled_permissions()
        
        # Format results for display and MQTT
        status_msg = {
            "timestamp": get_timestamp(),
            "rfid_id": rfid_id,
            "action": "enable_permissions",
            "enabled_permissions": [],
            "failed_permissions": []
        }
        
        print("\n=== PERMISSION ENABLE RESULTS FROM RFID SCAN ===")
        for perm, success in enabled_results.items():
            status = "✓ SUCCESS" if success else "✗ FAILED"
            print(f"{perm}: {status}")
            if success:
                status_msg["enabled_permissions"].append(perm)
            else:
                status_msg["failed_permissions"].append(perm)
        
        # Publish results
        client.publish(f"esp32/rfid_action/{device_id}", json.dumps(status_msg), qos=1)
        
        # Also publish an enable command to the standard topic for compatibility
        client.publish(enable_topic_subscribe, "enable_permissions", qos=1)
    elif rfid_id == target_rfid_disable_tag:
        print(f"Detected special RFID tag {target_rfid_disable_tag} - disabling permissions and closing apps")
        
        # First close any apps using camera/microphone
        print("\nClosing applications that use camera and microphone...")
        termination_results = terminate_invasive_apps()
        
        # Then disable all permissions
        disabled_results = disable_all_permissions()
        
        # Format results for display and MQTT
        status_msg = {
            "timestamp": get_timestamp(),
            "rfid_id": rfid_id,
            "action": "disable_permissions_and_close_apps",
            "disabled_permissions": [],
            "failed_permissions": [],
            "terminated_apps": {
                "camera": [app["name"] for app in termination_results["camera_apps"]],
                "microphone": [app["name"] for app in termination_results["microphone_apps"]],
                "terminated_count": termination_results["terminated_count"],
                "failed_count": termination_results["failed_count"]
            }
        }
        
        print("\n=== PERMISSION DISABLE RESULTS FROM RFID SCAN ===")
        for perm, success in disabled_results.items():
            status = "✓ SUCCESS" if success else "✗ FAILED"
            print(f"{perm}: {status}")
            if success:
                status_msg["disabled_permissions"].append(perm)
            else:
                status_msg["failed_permissions"].append(perm)
        
        # Publish results
        client.publish(f"esp32/rfid_action/{device_id}", json.dumps(status_msg), qos=1)
        
        # Also publish a disable command to the standard topic for compatibility
        client.publish(topic_subscribe, "disable_permissions", qos=1)
    else:
        print(f"Unknown RFID tag: {rfid_id} - no action taken")

# ===== Utility Functions =====
def get_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()

def get_system_info():
    """Get system information"""
    try:
        info = {
            "device_id": device_id,
            "hostname": platform.node(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "timestamp": get_timestamp()
        }
        
        # Add Windows-specific information
        if platform.system() == "Windows":
            # Get Windows edition
            try:
                cmd = r'wmic os get Caption /value'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    caption = result.stdout.strip()
                    if "Caption=" in caption:
                        info["windows_edition"] = caption.split("Caption=")[1].strip()
            except Exception:
                pass
                
            # Get uptime
            try:
                cmd = r'wmic os get LastBootUpTime /value'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    boot_time = result.stdout.strip()
                    if "LastBootUpTime=" in boot_time:
                        info["last_boot"] = boot_time.split("LastBootUpTime=")[1].strip()
            except Exception:
                pass
                
        return info
    except Exception as e:
        print(f"Error collecting system info: {e}")
        return {"device_id": device_id, "error": str(e)}

def categorize_software(software_list):
    """Categorize software for better organization"""
    categories = {
        "System": [],
        "Security": [],
        "Productivity": [],
        "Entertainment": [],
        "Development": [],
        "Utilities": [],
        "Other": []
    }
    
    # Keywords for categorization
    category_keywords = {
        "System": ["microsoft", "windows", "system", "driver", "intel", "amd", "nvidia", "realtek"],
        "Security": ["security", "antivirus", "firewall", "protection", "defender", "encrypt"],
        "Productivity": ["office", "word", "excel", "powerpoint", "document", "adobe", "pdf", "slack", "teams"],
        "Entertainment": ["game", "media", "player", "video", "audio", "music", "steam", "play"],
        "Development": ["visual studio", "code", "python", "java", "developer", "git", "node", "android studio"],
        "Utilities": ["utility", "tool", "manager", "monitor", "backup", "clean", "compress"]
    }
    
    for software in software_list:
        name = software["name"].lower()
        publisher = software["publisher"].lower()
        
        # Determine category
        assigned = False
        for category, keywords in category_keywords.items():
            if any(keyword in name or keyword in publisher for keyword in keywords):
                categories[category].append(software)
                assigned = True
                break
                
        # If not assigned to any specific category
        if not assigned:
            categories["Other"].append(software)
    
    # Remove empty categories
    return {k: v for k, v in categories.items() if v}

# ===== Software Listing Functions =====
def get_installed_software(display_local=False):
    """Get list of installed software from Windows registry"""
    software_list = []
    start_time = time.time()
    
    print("Fetching installed software from registry...")
    
    # Paths to registry keys containing installed software information
    reg_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    
    for reg_path in reg_paths:
        try:
            registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(registry, reg_path)
            
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    
                    try:
                        software_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        try:
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        except (WindowsError, FileNotFoundError):
                            version = "Unknown"
                            
                        try:
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                        except (WindowsError, FileNotFoundError):
                            publisher = "Unknown"
                            
                        install_location = ""
                        try:
                            install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                        except (WindowsError, FileNotFoundError):
                            pass
                            
                        # Get install date if available
                        install_date = ""
                        try:
                            install_date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                        except (WindowsError, FileNotFoundError):
                            pass
                        
                        software_list.append({
                            "name": software_name,
                            "version": version,
                            "publisher": publisher,
                            "install_location": install_location,
                            "install_date": install_date
                        })
                    except (WindowsError, FileNotFoundError):
                        # Skip entries without DisplayName
                        pass
                    finally:
                        try:
                            winreg.CloseKey(subkey)
                        except Exception:
                            pass
                except (WindowsError, FileNotFoundError, Exception) as e:
                    continue
            
            try:
                winreg.CloseKey(key)
                winreg.CloseKey(registry)
            except Exception:
                pass
                
        except (WindowsError, FileNotFoundError, Exception) as e:
            print(f"Error accessing registry path {reg_path}: {e}")
            continue
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # Sort the software list by name for better readability
    software_list = sorted(software_list, key=lambda x: x['name'])
    
    # Display the software list locally if requested
    if display_local:
        print(f"\n=== INSTALLED SOFTWARE LIST ({len(software_list)} items, {elapsed_time:.2f}s) ===")
        
        # Group by publisher for better organization
        by_publisher = {}
        for software in software_list:
            publisher = software["publisher"]
            if publisher not in by_publisher:
                by_publisher[publisher] = []
            by_publisher[publisher].append(software)
        
        # Display top publishers first (with most software)
        top_publishers = sorted(by_publisher.items(), key=lambda x: len(x[1]), reverse=True)
        
        for i, (publisher, software) in enumerate(top_publishers[:10]):
            print(f"\n{i+1}. Publisher: {publisher} ({len(software)} items)")
            for j, app in enumerate(sorted(software, key=lambda x: x['name'])[:5]):
                print(f"   {j+1}. {app['name']} - v{app['version']}")
            if len(software) > 5:
                print(f"   ... and {len(software) - 5} more items")
        
        if len(top_publishers) > 10:
            print(f"\n... and {len(top_publishers) - 10} more publishers")
        
        print("\n" + "="*50)
    
    return software_list

# ===== Permission Checking and Disabling =====
def check_permission(capability):
    """Generic permission checker using the CapabilityAccessManager"""
    try:
        cmd = f'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{capability}" /v "Value"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if "Allow" in result.stdout:
            return True
    except Exception as e:
        print(f"Error checking {capability} access: {e}")
    return False

def disable_permission(capability):
    """Generic permission disabler using the CapabilityAccessManager"""
    print(f"Disabling {capability}...")
    try:
        cmd = f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{capability}" /v "Value" /t REG_SZ /d "Deny" /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{capability.title()} disabled successfully")
            return True
        else:
            print(f"{capability.title()} disable error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error disabling {capability}: {e}")
        return False

def enable_permission(capability):
    """Generic permission enabler using the CapabilityAccessManager"""
    print(f"Enabling {capability}...")
    try:
        cmd = f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{capability}" /v "Value" /t REG_SZ /d "Allow" /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{capability.title()} enabled successfully")
            return True
        else:
            print(f"{capability.title()} enable error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error enabling {capability}: {e}")
        return False

def check_storage_access():
    """Check if USB storage is enabled"""
    try:
        # Check USB storage status
        cmd = r'reg query "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v "Start"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        # If Start is 3 (SERVICE_DEMAND_START) or 2 (SERVICE_AUTO_START), USB storage is enabled
        if "0x3" in result.stdout or "0x2" in result.stdout:
            return True
    except Exception as e:
        print(f"Error checking storage access: {e}")
    return False

def disable_storage():
    """Disable USB storage devices system-wide"""
    print("Disabling USB storage devices...")
    try:
        # This command sets the USBSTOR driver start value to 4 (disabled).
        # WARNING: This disables USB mass storage (external drives) until re-enabled.
        cmd = r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v "Start" /t REG_DWORD /d 4 /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("USB storage disabled successfully")
            return True
        else:
            print(f"USB storage disable error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error disabling USB storage: {e}")
        return False

def enable_storage():
    """Enable USB storage devices system-wide"""
    print("Enabling USB storage devices...")
    try:
        # Set USBSTOR driver start value to 3 (SERVICE_DEMAND_START)
        cmd = r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v "Start" /t REG_DWORD /d 3 /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("USB storage enabled successfully")
            return True
        else:
            print(f"USB storage enable error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error enabling USB storage: {e}")
        return False

def check_background_apps():
    """Check if background apps are enabled"""
    try:
        # Check background apps setting
        cmd = r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        # If GlobalUserDisabled is 0, background apps are enabled
        if "0x0" in result.stdout:
            return True
    except Exception as e:
        # If the key doesn't exist, background apps are likely enabled by default
        return True
    return False

def disable_background_apps():
    """Disable background apps for all users"""
    print("Disabling background apps...")
    try:
        # Disable background apps by setting GlobalUserDisabled to 1
        cmd = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("Background apps disabled successfully")
            return True
        else:
            print(f"Background apps disable error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error disabling background apps: {e}")
        return False

def enable_background_apps():
    """Enable background apps for all users"""
    print("Enabling background apps...")
    try:
        # Enable background apps by setting GlobalUserDisabled to 0
        cmd = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 0 /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("Background apps enabled successfully")
            return True
        else:
            print(f"Background apps enable error: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error enabling background apps: {e}")
        return False

def disable_all_permissions():
    """Disable all monitored permissions"""
    print("\nDisabling all permissions on Windows laptop...")
    results = {}
    disabled_list = []
    
    # Disable each permission in the permission categories
    for category, details in PERMISSION_CATEGORIES.items():
        print(f"\nAttempting to disable: {category}")
        disable_func = details["disable"]
        success = disable_func()
        results[category] = success
        status = "SUCCESS" if success else "FAILED"
        print(f"  Result: {status}")
        
        if success:
            disabled_list.append(category)
    
    # Update the disabled permissions history
    global disabled_permissions_history
    disabled_permissions_history = {
        "timestamp": get_timestamp(),
        "permissions": disabled_list
    }
    
    return results

def enable_all_permissions():
    """Enable all monitored permissions"""
    print("\nEnabling all permissions on Windows laptop...")
    results = {}
    
    # Enable each permission in the permission categories
    for category, details in PERMISSION_CATEGORIES.items():
        print(f"\nAttempting to enable: {category}")
        enable_func = details["enable"]
        success = enable_func()
        results[category] = success
        status = "SUCCESS" if success else "FAILED"
        print(f"  Result: {status}")
    
    return results

def enable_disabled_permissions():
    """Enable only the permissions that were previously disabled"""
    print("\nEnabling previously disabled permissions...")
    results = {}
    
    # Check if we have a history of disabled permissions
    global disabled_permissions_history
    if not disabled_permissions_history["permissions"]:
        print("No record of previously disabled permissions.")
        return {}
    
    print(f"Found {len(disabled_permissions_history['permissions'])} previously disabled permissions from {disabled_permissions_history['timestamp']}")
    
    # Enable each permission that was previously disabled
    for category in disabled_permissions_history["permissions"]:
        if category in PERMISSION_CATEGORIES:
            print(f"\nAttempting to enable: {category}")
            enable_func = PERMISSION_CATEGORIES[category]["enable"]
            success = enable_func()
            results[category] = success
            status = "SUCCESS" if success else "FAILED"
            print(f"  Result: {status}")
    
    # Clear the history after enabling
    if any(results.values()):
        disabled_permissions_history = {
            "timestamp": "",
            "permissions": []
        }
    
    return results

# ===== Core Scanning Function =====
def scan_software_and_permissions(client, disable_mode=False):
    """
    Comprehensive scan of software and permissions
    
    Args:
        client: MQTT client for publishing results
        disable_mode: Whether to disable invasive permissions (True) or just scan (False)
    
    Returns:
        Dictionary containing scan results
    """
    action = "scanning and disabling" if disable_mode else "scanning"
    print(f"\n=== Started {action} invasive permissions ===")
    
    # Track all the results
    scan_results = {
        "timestamp": get_timestamp(),
        "device_id": device_id,
        "hostname": platform.node(),
        "scan_mode": "disable" if disable_mode else "scan_only",
        "software": {
            "total": 0,
            "invasive": 0,
            "non_invasive": 0
        },
        "permissions": {
            "enabled_before": [],
            "disabled_successful": [],
            "disabled_failed": []
        },
        "invasive_software": [],
        "non_invasive_software": [],
        "software_permissions_map": {},
        "disabled_permissions_by_app": {}
    }
    
    # Step 1: Check which permissions are currently enabled
    print("\nChecking currently enabled permissions...")
    for category, details in PERMISSION_CATEGORIES.items():
        check_func = details["check"]
        if check_func():
            scan_results["permissions"]["enabled_before"].append(category)
            print(f"  ✓ {category}: ENABLED")
        else:
            print(f"  - {category}: Already disabled")
    
    if not scan_results["permissions"]["enabled_before"]:
        print("No permissions are currently enabled. Nothing to disable.")
        if disable_mode:
            client.publish(f"esp32/invasive_scan/{device_id}", json.dumps(scan_results), qos=1)
        return scan_results
    
    # Step 2: Get list of installed software
    software_list = get_installed_software()
    scan_results["software"]["total"] = len(software_list)
    
    # Step 3: Check each software for invasive categories
    print("\nChecking software for invasive permissions...")
    for software in software_list:
        software_name = software["name"]
        publisher = software["publisher"]
        
        # Track permissions for this software
        software_invasive_permissions = []
        software_disabled_permissions = []
        
        # Check each enabled permission against this software
        for category in scan_results["permissions"]["enabled_before"]:
            details = PERMISSION_CATEGORIES[category]
            keywords = details["keywords"]
            
            # Check if software matches keywords for this permission
            matches_keyword = any(keyword in software_name.lower() for keyword in keywords)
            matches_publisher = any(keyword in publisher.lower() for keyword in keywords)
            
            if matches_keyword or matches_publisher:
                # This software has invasive permissions
                software_invasive_permissions.append(category)
                
                # Disable if in disable mode
                if disable_mode:
                    disable_func = details["disable"]
                    success = disable_func()
                    
                    if success:
                        software_disabled_permissions.append(category)
                        if category not in scan_results["permissions"]["disabled_successful"]:
                            scan_results["permissions"]["disabled_successful"].append(category)
                    else:
                        if category not in scan_results["permissions"]["disabled_failed"]:
                            scan_results["permissions"]["disabled_failed"].append(category)
        
        # Store results for this software
        if software_invasive_permissions:
            # Add to invasive software list
            invasive_entry = {
                "name": software_name,
                "publisher": publisher,
                "version": software["version"],
                "invasive_permissions": software_invasive_permissions,
                "disabled_permissions": software_disabled_permissions if disable_mode else []
            }
            
            scan_results["invasive_software"].append(invasive_entry)
            scan_results["software_permissions_map"][software_name] = software_invasive_permissions
            
            if disable_mode and software_disabled_permissions:
                scan_results["disabled_permissions_by_app"][software_name] = software_disabled_permissions
        else:
            # Add to non-invasive list
            scan_results["non_invasive_software"].append({
                "name": software_name,
                "publisher": publisher,
                "version": software["version"]
            })
    
    # Update software counts
    scan_results["software"]["invasive"] = len(scan_results["invasive_software"])
    scan_results["software"]["non_invasive"] = len(scan_results["non_invasive_software"])
    
    # Step 4: Display detailed report
    print("\n=== SOFTWARE SCAN RESULTS ===")
    print(f"Total software: {scan_results['software']['total']}")
    print(f"Software with invasive permissions: {scan_results['software']['invasive']}")
    print(f"Software without invasive permissions: {scan_results['software']['non_invasive']}")
    
    if scan_results["invasive_software"]:
        print("\nDetailed list of software with invasive permissions:")
        for i, software in enumerate(scan_results["invasive_software"][:10]):  # Show first 10
            print(f"\n{i+1}. {software['name']} (by {software['publisher']})")
            print(f"   Invasive permissions: {', '.join(software['invasive_permissions'])}")
            
            if disable_mode:
                if software['disabled_permissions']:
                    print(f"   ✓ Disabled permissions: {', '.join(software['disabled_permissions'])}")
                
                failed_perms = [p for p in software['invasive_permissions'] if p not in software['disabled_permissions']]
                if failed_perms:
                    print(f"   ✗ Failed to disable: {', '.join(failed_perms)}")
        
        if len(scan_results["invasive_software"]) > 10:
            print(f"\n... and {len(scan_results['invasive_software']) - 10} more invasive software")
    else:
        print("\nNo software with invasive permissions detected")
    
    # Permission summary
    print("\n=== PERMISSION SUMMARY ===")
    print(f"Permissions enabled before scan: {', '.join(scan_results['permissions']['enabled_before'])}")
    
    if disable_mode:
        print(f"\nPermissions successfully disabled: {', '.join(scan_results['permissions']['disabled_successful'])}")
        print(f"Permissions failed to disable: {', '.join(scan_results['permissions']['disabled_failed'])}")
    
    print("\n" + "="*50)
    
    # Publish results if in disable mode
    if disable_mode:
        client.publish(f"esp32/invasive_scan/{device_id}", json.dumps(scan_results), qos=1)
    else:
        client.publish(f"esp32/invasive_scan_only/{device_id}", json.dumps(scan_results), qos=1)
    
    return scan_results

def setup_mqtt_client():
    """Set up and configure the MQTT client"""
    # Create the client with MQTTv5 protocol
    client_id = f"windows_{device_id}_{int(time.time())}"  # Add timestamp for uniqueness
    client = paho.Client(client_id=client_id, userdata=None, protocol=paho.MQTTv5)
    
    # Set callbacks
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    client.on_subscribe = on_subscribe
    client.on_message = on_message

    # Enable TLS for secure connection using the default trusted CAs.
    try:
        client.tls_set(tls_version=mqtt.client.ssl.PROTOCOL_TLS)
    except Exception as e:
        print(f"Error setting up TLS: {e}")
        sys.exit(1)
        
    # Set username and password
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

    # Set last will testament to notify if this client disconnects unexpectedly
    client.will_set(f"esp32/status/{device_id}", payload="offline", qos=1, retain=True)
    
    return client

def print_banner():
    """Print a welcome banner with information about the script"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                WINDOWS SECURITY MANAGER v2.2                  ║
║                                                              ║
║  Device ID: {device_id:<46} ║
║  MQTT Broker: {MQTT_BROKER:<42} ║
║  Disable Topic: {topic_subscribe:<42} ║
║  Enable Topic: {enable_topic_subscribe:<44} ║
║  RFID Scan Topic: {rfid_topic:<40} ║
║  Enable RFID Tag: {target_rfid_enable_tag:<40} ║
║  Disable RFID Tag: {target_rfid_disable_tag:<40} ║
╚══════════════════════════════════════════════════════════════╝

This script monitors and manages invasive permissions on Windows:
• Lists all installed software with detailed information
• Identifies software with potentially invasive permissions
• Disables invasive permissions on command
• Terminates applications using camera/microphone
• Enables permissions when specific RFID tag is scanned
• Reports permission status changes in detail

Available commands on {topic_subscribe}:
1. list_software       - List all installed software
2. scan_only           - Scan for invasive software without disabling
3. scan_and_disable_invasive - Scan and disable invasive permissions
4. disable_permissions - Disable all permissions and close invasive apps
5. system_info         - Show system information

Available commands on {enable_topic_subscribe}:
1. enable_permissions           - Enable all permissions
2. enable_disabled_permissions  - Enable only previously disabled permissions

RFID scanning on {rfid_topic}:
• Scanning tag {target_rfid_enable_tag} will automatically enable previously disabled permissions
• Scanning tag {target_rfid_disable_tag} will disable all permissions and terminate camera/microphone apps
"""
    print(banner)

def main():
    """Main entry point of the script"""
    # Request administrator privileges if not already running as admin
    ensure_admin()
    
    # Print welcome banner
    print_banner()
    
    # Set up MQTT client
    client = setup_mqtt_client()

    print("Connecting to MQTT broker securely...")
    try:
        # Connect to broker
        client.connect(MQTT_BROKER, MQTT_PORT)
        
        # Publish online status
        client.publish(f"esp32/status/{device_id}", "online", qos=1, retain=True)
        
        # Send system information
        system_info = get_system_info()
        client.publish(f"esp32/system_info/{device_id}", json.dumps(system_info), qos=1)
        print("Published system information to MQTT")
        
        # Perform initial permission scan without disabling
        print("\nPerforming initial permission scan...")
        initial_scan = scan_software_and_permissions(client, disable_mode=False)
        
        # Display summary of initial scan
        print("\n=== INITIAL SCAN SUMMARY ===")
        print(f"Total Software: {initial_scan['software']['total']}")
        print(f"Software with invasive permissions: {initial_scan['software']['invasive']}")
        if initial_scan['permissions']['enabled_before']:
            print(f"Enabled permissions: {', '.join(initial_scan['permissions']['enabled_before'])}")
        else:
            print("No invasive permissions are currently enabled")
        
        print("\nWaiting for commands...")
        print("Use Ctrl+C to exit the script")
        
        # ===== Main Loop =====
        client.loop_forever()
        
    except KeyboardInterrupt:
        print("\nScript terminated by user")
        try:
            client.publish(f"esp32/status/{device_id}", "offline", qos=1, retain=True)
            client.disconnect()
            print("Disconnected from MQTT broker")
        except Exception as e:
            print(f"Error during clean shutdown: {e}")
    except Exception as e:
        print(f"Connection error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 
