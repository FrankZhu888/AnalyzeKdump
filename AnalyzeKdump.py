#!/usr/bin/env python3
# Written by Frank Zhu <frz@microsoft.com>              02.25.2025
# Updated to support both RHEL 8 and RHEL 9 releases    03.12.2025

import subprocess
import os
import sys
import platform
import re
from jinja2 import Template
from datetime import datetime

# Default output file path
DEFAULT_OUTPUT_HTML = "kdump_analysis_report.html"

# Display usage instructions
def print_usage():
    usage = """
Usage: # ./AnalyzeKdump.py --vmcore <vmcore_path> --vmlinux <vmlinux_path> [--output <output_html>]

Description:
    Analyzes a kdump vmcore file on RHEL 8 and RHEL 9 systems to identify performance issues causing VM hangs,
    including D state processes, hung tasks, potential hung causes, backtraces, kernel logs, and system memory info.
    Outputs results to an HTML report.

Required Arguments:
    --vmcore    Path to the vmcore file (e.g., /var/crash/127.0.0.1-2025-02-25-08:03:04/vmcore)
    --vmlinux   Path to the vmlinux file with debug symbols (e.g., /usr/lib/debug/lib/modules/$(uname -r)/vmlinux)

Optional Arguments:
    --output    Path to the output HTML report (default: kdump_analysis_report.html)

Example:
    # ./AnalyzeKdump.py --vmcore /var/crash/127.0.0.1-2025-02-25-08:03:04/vmcore \\
                                  --vmlinux /usr/lib/debug/lib/modules/5.14.0-162.el9.x86_64/vmlinux \\
                                  --output report.html

Notes:
    - Requires root privileges (sudo) to install crash tools if not present.
    - Ensure the vmcore and vmlinux files match the crashed kernel version.

Support Contact:        Frank Zhu <frz@microsoft.com>   Microsoft Azure Linux Escalation Team
    """
    print(usage)

# Print progress with timestamp and optional color
def log_progress(message, color=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if color == "red":
        print(f"\033[31m[{timestamp}] {message}\033[0m")
    elif color == "green":
        print(f"\033[32m[{timestamp}] {message}\033[0m")
    else:
        print(f"[{timestamp}] {message}")

# Check and install crash environment if not present
def setup_crash_environment():
    log_progress("Checking crash environment...")
    try:
        subprocess.run(["crash", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_progress("Crash environment is already installed, skipping setup.")
    except FileNotFoundError:
        log_progress("Crash not found, installing crash environment...")
        try:
            subprocess.run(["sudo", "dnf", "install", "-y", "crash"], check=True)
            log_progress("Crash environment installed successfully.")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to install crash environment: {e}")

# Detect RHEL version
def get_rhel_version():
    """
    Detect the RHEL version of the current system.
    Returns '8' for RHEL 8, '9' for RHEL 9, or raises an exception if undetermined.
    """
    try:
        with open("/etc/os-release", "r") as f:
            content = f.read()
            match = re.search(r'VERSION_ID="(\d+)\.\d+"', content)
            if match:
                major_version = match.group(1)
                if major_version in ["8", "9"]:
                    return major_version
        # Fallback to platform if os-release fails
        release = platform.release()
        if "el8" in release:
            return "8"
        elif "el9" in release:
            return "9"
        raise Exception("Unable to determine RHEL version.")
    except Exception as e:
        log_progress(f"Error detecting RHEL version: {e}")
        raise Exception("System version detection failed. Ensure running on RHEL 8 or 9.")

# RHEL 8 specific crash command execution and filtering
def run_crash_command_rhel8(command, vmcore_path, vmlinux_path, debug=False):
    """
    Execute a crash command on RHEL 8 and return its filtered output.
    Designed for crash 7 without 'crash>' prompt.
    """
    full_cmd = ["crash", vmlinux_path, vmcore_path]
    process = subprocess.Popen(full_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1024*1024)
    stdout, stderr = process.communicate(input=f"{command}\nquit\n")

    if debug:
        log_progress(f"Raw output for '{command}' (RHEL 8):\n{stdout}")

    if process.returncode != 0:
        raise Exception(f"Crash command failed: {stderr}\nCommand: {command}\nFull command: {' '.join(full_cmd)}")

    lines = stdout.splitlines()
    filtered_output = []
    state_found = False
    capture = False

    for line in lines:
        # Skip copyright and irrelevant lines
        if any(keyword in line for keyword in [
            "crash ", "Copyright", "GNU gdb (GDB)", "This GDB was configured", "Type", "For help",
            "please wait...", "NOTE: stdin: not a tty", "quit", "License GPLv3+", "This program",
            "show copying", "show warranty", "free software", "no warranty"
        ]):
            continue

        # Skip system initialization info until STATE:
        if "STATE:" in line:
            state_found = True
            continue

        # After STATE:, wait for blank line to start capturing
        if state_found and not line.strip() and not capture:
            capture = True
            continue

        if capture:
            filtered_output.append(line)

    output = "\n".join(filtered_output).strip()

    if debug:
        log_progress(f"Filtered output for '{command}' (RHEL 8):\n{output}")

    if not output:
        log_progress(f"Warning: No valid output from command '{command}'")

    return output

# RHEL 9 specific crash command execution and filtering
def run_crash_command_rhel9(command, vmcore_path, vmlinux_path, debug=False):
    """
    Execute a crash command on RHEL 9 and return its filtered output.
    Designed for crash 8.0.5 with 'crash>' prompt.
    """
    full_cmd = ["crash", vmlinux_path, vmcore_path]
    process = subprocess.Popen(full_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1024*1024)
    stdout, stderr = process.communicate(input=f"{command}\nquit\n")

    if debug:
        log_progress(f"Raw output for '{command}' (RHEL 9):\n{stdout}")

    if process.returncode != 0:
        raise Exception(f"Crash command failed: {stderr}\nCommand: {command}\nFull command: {' '.join(full_cmd)}")

    lines = stdout.splitlines()
    filtered_output = []
    capture = False

    for line in lines:
        if line.startswith("crash ") and "Copyright" in line:
            continue
        if "GNU gdb (GDB)" in line or "This GDB was configured" in line or "Type" in line or "For help" in line:
            continue
        if "please wait..." in line:
            continue
        if line.startswith("crash>"):
            capture = True
            continue
        if capture and line.strip() == "quit":
            break
        if capture:
            filtered_output.append(line)

    output = "\n".join(filtered_output).strip()

    if debug:
        log_progress(f"Filtered output for '{command}' (RHEL 9):\n{output}")

    if not output:
        log_progress(f"Warning: No valid output from command '{command}'")

    return output

# Analyze D state processes and their backtraces
def analyze_d_state_processes(vmcore_path, vmlinux_path, run_crash_command):
    log_progress("Analyzing D state processes...")
    ps_output = run_crash_command("ps", vmcore_path, vmlinux_path)
    d_state_procs = []
    for line in ps_output.splitlines():
        if " UN " in line:
            pid = line.split()[0]
            proc_name = line.split()[-1]
            log_progress(f"Found D state process: PID {pid} ({proc_name}), analyzing backtrace...")
            bt_output = run_crash_command(f"bt {pid}", vmcore_path, vmlinux_path)
            d_state_procs.append({"pid": pid, "name": proc_name, "backtrace": bt_output})
    log_progress("D state processes analysis completed.")
    return d_state_procs

# Analyze hung tasks from kernel logs
def analyze_hung_tasks(vmcore_path, vmlinux_path, run_crash_command):
    log_progress("Analyzing hung tasks...")
    log_output = run_crash_command("log", vmcore_path, vmlinux_path)
    hung_tasks = []
    log_lines = log_output.splitlines()
    i = 0
    while i < len(log_lines):
        line = log_lines[i]
        if "blocked for more than" in line.lower():
            log_progress(f"Detected potential hung task line: {line}")
            pid = None
            proc_name = None
            blocked_time = None
            call_trace = []
            try:
                parts = line.split()
                task_idx = parts.index("task")
                task_info = parts[task_idx + 1]
                proc_name, pid = task_info.split(":")
                blocked_idx = next((j for j in range(task_idx, len(parts)) if "blocked" in parts[j].lower()), None)
                seconds_idx = next((j for j in range(blocked_idx, len(parts)) if "seconds" in parts[j].lower()), None)
                if blocked_idx and seconds_idx:
                    blocked_time = " ".join(parts[blocked_idx:seconds_idx+1])
                else:
                    blocked_time = "Blocked time unspecified"
            except Exception as e:
                log_progress(f"Error parsing hung task line '{line}': {e}")
                i += 1
                continue
            i += 1
            while i < len(log_lines) and "Call Trace:" in log_lines[i]:
                i += 1
                while i < len(log_lines) and log_lines[i].strip() and not log_lines[i].startswith("["):
                    call_trace.append(log_lines[i].strip())
                    i += 1
                break
            if pid:
                log_progress(f"Found hung task in logs: PID {pid} ({proc_name}), analyzing backtrace...")
                bt_output = run_crash_command(f"bt {pid}", vmcore_path, vmlinux_path)
                hung_tasks.append({
                    "pid": pid,
                    "name": proc_name,
                    "blocked_time": blocked_time,
                    "backtrace": "\n".join(call_trace) if call_trace else bt_output
                })
            else:
                log_progress(f"Could not extract PID from hung task line: {line}")
        i += 1
    log_progress("Hung tasks analysis completed.")
    return hung_tasks

# Analyze kernel logs for errors, warnings, and bug related events
def analyze_kernel_logs(vmcore_path, vmlinux_path, run_crash_command):
    log_progress("Analyzing kernel logs...")
    log_output = run_crash_command("log", vmcore_path, vmlinux_path)
    log_lines = log_output.splitlines()

    # Define bug related keywords
    bug_keywords = ["error", "failed", "warn", "warning", "oops", "bug", "leak", "invalid", "deadlock"]

    # Filter logs containing any of the bug related keywords (case-insensitive)
    filtered_logs = [line for line in log_lines if any(keyword in line.lower() for keyword in bug_keywords)]

    log_progress("Kernel logs analysis completed.")
    return "\n".join(filtered_logs) if filtered_logs else "No errors, warnings, or bug related events found in kernel logs."

# Analyze system performance metrics
def analyze_performance(vmcore_path, vmlinux_path, run_crash_command):
    log_progress("Analyzing system performance metrics...")
    sys_info = run_crash_command("sys", vmcore_path, vmlinux_path)
    mem_info = run_crash_command("kmem -i", vmcore_path, vmlinux_path)
    log_progress("Analyzing top memory consuming processes...")
    ps_output = run_crash_command("ps", vmcore_path, vmlinux_path)
    processes = []

    if not ps_output:
        log_progress("No process data available from 'ps' command.")
        return {"sys_info": sys_info, "mem_info": mem_info, "top_processes": processes}

    lines = ps_output.splitlines()
    if not lines:
        log_progress("Empty process output.")
        return {"sys_info": sys_info, "mem_info": mem_info, "top_processes": processes}

    # Find header dynamically
    header_line = None
    for i, line in enumerate(lines):
        if "PID" in line and "COMM" in line:
            header_line = lines[i]
            data_start = i + 1
            break

    if not header_line:
        log_progress("Error: No valid header found in 'ps' output.")
        return {"sys_info": sys_info, "mem_info": mem_info, "top_processes": processes}

    header = header_line.split()
    try:
        pid_idx = header.index("PID")
        ppid_idx = header.index("PPID")
        cpu_idx = header.index("CPU")
        state_idx = header.index("ST")
        mem_idx = header.index("%MEM")
        vsz_idx = header.index("VSZ")
        rss_idx = header.index("RSS")
        comm_idx = header.index("COMM")
    except ValueError as e:
        log_progress(f"Error: Invalid header format: {header}, missing column: {str(e)}")
        return {"sys_info": sys_info, "mem_info": mem_info, "top_processes": processes}

    for line in lines[data_start:]:
        if line.strip().startswith(">"):
            continue
        parts = line.split()
        if len(parts) >= comm_idx + 1:
            try:
                pid = parts[pid_idx]
                ppid = parts[ppid_idx]
                cpu = parts[cpu_idx]
                state = parts[state_idx]
                mem_percent = float(parts[mem_idx])
                vsz = parts[vsz_idx]
                rss = parts[rss_idx]
                comm = " ".join(parts[comm_idx:])
                processes.append({
                    "pid": pid,
                    "ppid": ppid,
                    "cpu": cpu,
                    "state": state,
                    "mem_percent": mem_percent,
                    "vsz": vsz,
                    "rss": rss,
                    "comm": comm
                })
            except (ValueError, IndexError) as e:
                log_progress(f"Skipping malformed ps line '{line}': {e}")
                continue

    top_processes = sorted(processes, key=lambda x: x["mem_percent"], reverse=True)[:9]
    log_progress("System performance metrics analysis completed.")
    return {"sys_info": sys_info, "mem_info": mem_info, "top_processes": top_processes}

# Analyze additional hung causes
def analyze_hung_causes(vmcore_path, vmlinux_path, run_crash_command):
    log_progress("Analyzing potential hung causes...")

    # Check memory pressure
    log_progress("Checking memory pressure...")
    mem_info = run_crash_command("kmem -i", vmcore_path, vmlinux_path)
    log_output = run_crash_command("log", vmcore_path, vmlinux_path)
    oom_messages = [line for line in log_output.splitlines() if "Out of memory" in line or "oom-killer" in line]
    memory_pressure = {"mem_info": mem_info, "oom_logs": "\n".join(oom_messages) if oom_messages else "No OOM events detected."}

    # Check CPU scheduling issues
    log_progress("Checking CPU scheduling (run queue)...")
    runq_output = run_crash_command("runq", vmcore_path, vmlinux_path)

    # Check kernel panic and extract everything from "Kernel panic" to the end
    log_progress("Checking kernel panic...")
    sys_output = run_crash_command("sys", vmcore_path, vmlinux_path)
    panic_info = next((line for line in sys_output.splitlines() if "PANIC" in line), "No panic information available.")

    panic_trace = "No panic trace available."
    if "No panic information available." not in panic_info:
        log_lines = log_output.splitlines()
        panic_trace_lines = []
        panic_found = False
        i = 0
        while i < len(log_lines):
            if "Kernel panic" in log_lines[i]:
                log_progress(f"Found Kernel panic at line {i}")
                panic_found = True
                while i < len(log_lines):
                    panic_trace_lines.append(log_lines[i].strip())
                    i += 1
                break
            i += 1
        if panic_found and panic_trace_lines:
            panic_trace = "\n".join(panic_trace_lines)
            log_progress("Successfully extracted panic trace from Kernel panic to end.")
        else:
            log_progress("No Kernel panic trace found in log")

    # Check I/O subsystem issues
    log_progress("Checking I/O subsystem issues...")
    io_errors = [line for line in log_output.splitlines() if "I/O" in line or "blk" in line or "scsi" in line]
    io_issues = "\n".join(io_errors) if io_errors else "No I/O related errors detected."

    # Check interrupt statistics
    log_progress("Checking interrupt statistics...")
    irq_output = run_crash_command("irq", vmcore_path, vmlinux_path)
    filtered_irqs = []
    for line in irq_output.splitlines():
        if "(unused)" not in line:
            filtered_irqs.append(line)
    irq_summary = "\n".join(filtered_irqs) if filtered_irqs else "No active interrupts detected."

    # Check network devices
    log_progress("Checking network devices...")
    net_devices = run_crash_command("dev -i", vmcore_path, vmlinux_path)

    log_progress("Potential hung causes analysis completed.")
    return {
        "memory_pressure": memory_pressure,
        "runq": runq_output,
        "panic_info": panic_info,
        "panic_trace": panic_trace,
        "io_issues": io_issues,
        "irq": irq_summary,
        "net_devices": net_devices
    }

# Analyze backtraces and call traces to generate conclusions
def analyze_traces(d_state_procs, hung_tasks, hung_causes):
    conclusions = []

    # Analyze D State Processes Backtraces
    for proc in d_state_procs:
        backtrace = proc["backtrace"]
        if "schedule_timeout" in backtrace or "msleep" in backtrace:
            conclusion = f"Process {proc['name']} (PID: {proc['pid']}) appears to be blocked in an uninterruptible sleep state (D state), possibly waiting for a resource or timer. Check for resource contention or timeouts in related modules."
            conclusions.append(conclusion)
        elif "oops" in backtrace.lower() or "bug" in backtrace.lower():
            conclusion = f"Process {proc['name']} (PID: {proc['pid']}) encountered a kernel oops or bug. Investigate kernel logs for specific errors."
            conclusions.append(conclusion)
        elif "schedule" not in backtrace and "sleep" not in backtrace:
            conclusion = f"Process {proc['name']} (PID: {proc['pid']}) may be CPU intensive, as it lacks scheduling or sleep calls in its backtrace. Verify if it contributes to high CPU usage."
            conclusions.append(conclusion)
        if "blk_" in backtrace or "scsi_" in backtrace or "wait_for_completion" in backtrace:
            conclusion = f"Process {proc['name']} (PID: {proc['pid']}) may be involved in heavy IO operations, potentially blocking on disk or device access."
            conclusions.append(conclusion)
        if "netif_" in backtrace or "tcp_" in backtrace or "sock_" in backtrace:
            conclusion = f"Process {proc['name']} (PID: {proc['pid']}) may be blocked on network operations. Check network stack or driver issues."
            conclusions.append(conclusion)
        if "ksoftirqd" in proc["name"].lower():
            conclusion = f"SoftIRQ process {proc['name']} (PID: {proc['pid']}) is active, potentially indicating high network load or interrupt issues."
            conclusions.append(conclusion)

    # Analyze Hung Tasks Backtraces
    for task in hung_tasks:
        backtrace = task["backtrace"]
        blocked_time = task["blocked_time"]
        if "schedule_timeout" in backtrace or "msleep" in backtrace:
            conclusion = f"Hung task {task['name']} (PID: {task['pid']}) blocked for {blocked_time}, likely waiting for a resource or driver operation. Check for deadlocks or delays in module '{extract_module(backtrace)}'."
            conclusions.append(conclusion)
        elif "deadlock" in backtrace.lower():
            conclusion = f"Hung task {task['name']} (PID: {task['pid']}) indicates a potential deadlock. Review resource locks in the call stack."
            conclusions.append(conclusion)
        if "blk_" in backtrace or "scsi_" in backtrace or "wait_for_completion" in backtrace:
            conclusion = f"Hung task {task['name']} (PID: {task['pid']}) blocked for {blocked_time} may be involved in heavy IO operations, potentially blocking on disk or device access."
            conclusions.append(conclusion)
        if "netif_" in backtrace or "tcp_" in backtrace or "sock_" in backtrace:
            conclusion = f"Hung task {task['name']} (PID: {task['pid']}) blocked for {blocked_time} may be related to network operations. Investigate network stack or driver."
            conclusions.append(conclusion)

    # Analyze Panic Trace
    if hung_causes["panic_trace"] != "No panic trace available.":
        panic_trace = hung_causes["panic_trace"]
        if "sysrq_handle_crash" in panic_trace:
            conclusion = "Kernel panic was manually triggered via SysRq (likely 'crash' command). This is an intentional crash, possibly for testing kdump functionality."
            conclusions.append(conclusion)
        elif "oops" in panic_trace.lower() or "bug" in panic_trace.lower():
            conclusion = "Kernel panic triggered by an oops or bug. Check kernel logs for preceding errors or memory corruption."
            conclusions.append(conclusion)
        elif "schedule" in panic_trace and "timeout" in panic_trace:
            conclusion = "Kernel panic may be related to a scheduling timeout. Investigate processes or drivers causing delays."
            conclusions.append(conclusion)
        if "netif_" in panic_trace or "tcp_" in panic_trace or "sock_" in panic_trace:
            conclusion = "Kernel panic may be related to network operations. Investigate network stack or driver issues."
            conclusions.append(conclusion)

    return "\n".join(conclusions) if conclusions else "No specific issues identified from the traces."

# Helper function to extract module name from trace
def extract_module(trace):
    for line in trace.splitlines():
        if "[" in line and "]" in line:
            module = line.split("[")[1].split("]")[0].strip()
            return module if module else "unknown"
    return "unknown"

# Generate HTML report with additional analysis conclusions and network info
def generate_html_report(d_state_procs, hung_tasks, perf_data, kernel_logs, hung_causes, output_file):
    log_progress("Generating HTML report...")

    # Generate analysis conclusions
    analysis_conclusions = analyze_traces(d_state_procs, hung_tasks, hung_causes)

    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Kdump Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            table { border-collapse: collapse; width: 80%; margin: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background-color: #f2f2f2; }
            pre { background-color: #f8f8f8; padding: 10px; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <h1>Kdump Analysis Report</h1>
        <p>Generated on: {{ timestamp }} | Support Contact: <a href="mailto:frz@microsoft.com">frz@microsoft.com</a> Microsoft Azure Linux Escalation Team</p>

        <h2>Analysis Conclusions</h2>
        <pre>{{ analysis_conclusions }}</pre>

        <h2>System Information</h2>
        <pre>{{ perf_data.sys_info }}</pre>

        <h2>Memory Information</h2>
        <pre>{{ perf_data.mem_info }}</pre>

        <h2>Kernel Logs (Errors/Warnings/Bugs)</h2>
        <pre>{{ kernel_logs }}</pre>

        <h2>D State Processes and Backtraces</h2>
        {% if d_state_procs %}
        <table>
            <tr><th>PID</th><th>Process Name</th><th>Backtrace</th></tr>
            {% for proc in d_state_procs %}
            <tr>
                <td>{{ proc.pid }}</td>
                <td>{{ proc.name }}</td>
                <td><pre>{{ proc.backtrace }}</pre></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No D state processes found.</p>
        {% endif %}

        <h2>Hung Tasks and Backtraces</h2>
        {% if hung_tasks %}
        <table>
            <tr><th>PID</th><th>Process Name</th><th>Blocked Time</th><th>Backtrace</th></tr>
            {% for task in hung_tasks %}
            <tr>
                <td>{{ task.pid }}</td>
                <td>{{ task.name }}</td>
                <td>{{ task.blocked_time }}</td>
                <td><pre>{{ task.backtrace }}</pre></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No hung tasks found.</p>
        {% endif %}

        <h2>Potential Hung Causes</h2>
        <h3>Kernel Panic</h3>
        <pre>{{ hung_causes.panic_info }}</pre>
        <p>Panic Trace: <pre>{{ hung_causes.panic_trace }}</pre></p>

        <h3>CPU Scheduling (Run Queue)</h3>
        <pre>{{ hung_causes.runq }}</pre>

        <h3>Memory Pressure</h3>
        <pre>{{ hung_causes.memory_pressure.mem_info }}</pre>
        <p>OOM Events: <pre>{{ hung_causes.memory_pressure.oom_logs }}</pre></p>
        <h4>Top 9 Memory Consuming Processes</h4>
        {% if perf_data.top_processes %}
        <table>
            <tr><th>PID</th><th>PPID</th><th>CPU</th><th>State</th><th>%MEM</th><th>VSZ</th><th>RSS</th><th>Command</th></tr>
            {% for proc in perf_data.top_processes %}
            <tr>
                <td>{{ proc.pid }}</td>
                <td>{{ proc.ppid }}</td>
                <td>{{ proc.cpu }}</td>
                <td>{{ proc.state }}</td>
                <td>{{ proc.mem_percent }}</td>
                <td>{{ proc.vsz }}</td>
                <td>{{ proc.rss }}</td>
                <td>{{ proc.comm }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No process memory data available.</p>
        {% endif %}

        <h3>I/O Subsystem Issues</h3>
        <pre>{{ hung_causes.io_issues }}</pre>

        <h3>Network Devices</h3>
        <pre>{{ hung_causes.net_devices }}</pre>

        <h3>Interrupt Statistics</h3>
        <pre>{{ hung_causes.irq }}</pre>

    </body>
    </html>
    """
    template = Template(template_str)
    html_content = template.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        d_state_procs=d_state_procs,
        hung_tasks=hung_tasks,
        perf_data=perf_data,
        kernel_logs=kernel_logs,
        hung_causes=hung_causes,
        analysis_conclusions=analysis_conclusions
    )
    with open(output_file, "w") as f:
        f.write(html_content)
    log_progress("HTML report generation completed.")

# Main function with argument parsing and progress logging
def main():
    log_progress("Initiating AnalyzeKdump for kdump analysis...", color="red")
    if len(sys.argv) < 5:
        print_usage()
        sys.exit(1)

    vmcore_path = None
    vmlinux_path = None
    output_file = DEFAULT_OUTPUT_HTML

    # Parse command-line arguments
    for i in range(1, len(sys.argv), 2):
        if sys.argv[i] == "--vmcore":
            vmcore_path = sys.argv[i + 1]
        elif sys.argv[i] == "--vmlinux":
            vmlinux_path = sys.argv[i + 1]
        elif sys.argv[i] == "--output":
            output_file = sys.argv[i + 1]
        else:
            print(f"Unknown argument: {sys.argv[i]}")
            print_usage()
            sys.exit(1)

    if not vmcore_path or not vmlinux_path:
        print("Error: --vmcore and --vmlinux are required arguments.")
        print_usage()
        sys.exit(1)

    try:
        # Detect RHEL version and select appropriate crash command function
        rhel_version = get_rhel_version()
        if rhel_version == "8":
            run_crash_command = run_crash_command_rhel8
            log_progress("RHEL 8 detected, applying RHEL 8 specific settings.")
        else:  # rhel_version == "9"
            run_crash_command = run_crash_command_rhel9
            log_progress("RHEL 9 detected, applying RHEL 9 specific settings.")

        # Check and setup crash environment
        setup_crash_environment()

        # Analyze D state processes and backtraces
        d_state_procs = analyze_d_state_processes(vmcore_path, vmlinux_path, run_crash_command)

        # Analyze hung tasks
        hung_tasks = analyze_hung_tasks(vmcore_path, vmlinux_path, run_crash_command)

        # Analyze additional hung causes
        hung_causes = analyze_hung_causes(vmcore_path, vmlinux_path, run_crash_command)

        # Analyze kernel logs
        kernel_logs = analyze_kernel_logs(vmcore_path, vmlinux_path, run_crash_command)

        # Analyze performance data
        perf_data = analyze_performance(vmcore_path, vmlinux_path, run_crash_command)

        # Generate report with analysis conclusions
        generate_html_report(d_state_procs, hung_tasks, perf_data, kernel_logs, hung_causes, output_file)

        log_progress(f"Analysis completed. Report saved to {output_file}", color="green")
    except Exception as e:
        log_progress(f"Error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
