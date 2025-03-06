# AnalyzeKdump

## Description
`AnalyzeKdump` is a Python script designed to analyze Linux kdump vmcore files for diagnosing VM hangs and performance issues. It extracts critical information such as D-state processes, hung tasks, kernel logs, system performance metrics, and potential hung causes (e.g., memory pressure, CPU scheduling, I/O issues, and interrupt statistics). The results are presented in a concise HTML report, making it easy to identify root causes of system failures.

This tool is particularly useful for system administrators and support engineers working with Red Hat Enterprise Linux (RHEL) or similar distributions.

## Features
- Analyzes D-state processes: Examines processes in uninterruptible sleep (UN state) with detailed backtraces to identify potential blockages.
- Identifies hung tasks: Detects tasks blocked for extended periods (e.g., "blocked for more than X seconds") from kernel logs, including associated backtraces.
- Evaluates system performance metrics: Collects system information (sys), memory usage (kmem -i), and top memory-consuming processes for performance insights.
- Detects potential hung causes: Analyzes multiple factors including:
        Memory pressure (with OOM events).
        CPU scheduling issues (run queue).
        I/O subsystem problems (e.g., block or SCSI issues).
        Interrupt statistics (IRQ activity).
        Network device status (dev -i) and network-related blockages.
- Provides detailed trace analysis: Generates conclusions from backtraces, identifying CPU-intensive tasks, I/O operations (e.g., blk_, scsi_), and network-related issues (e.g., netif_, tcp_, sock_).
- Generates an HTML report: Produces a comprehensive HTML report (kdump_analysis_report.html) with structured findings, including system info, logs, and analysis conclusions.

## Requirements
- Python 3.x
- `crash` utility (install via `dnf install crash`)
- `kernel-debuginfo` (install via `debuginfo-install kernel`)
- Root privileges for execution

## Usage
`# ./AnalyzeKdump.py --vmcore <vmcore_path> --vmlinux <vmlinux_path> [--output <output_html>]`

![image](https://github.com/user-attachments/assets/5bf6d2cb-4296-41c1-991f-3ffc094808ab)

## Example
`# ./AnalyzeKdump.py --vmcore /var/crash/127.0.0.1-2025-02-25-08:03:04/vmcore --vmlinux /usr/lib/debug/lib/modules/5.14.0-162.el9.x86_64/vmlinux`

![image](https://github.com/user-attachments/assets/687ce0ba-e998-4977-9c5b-3669fdd0a77b)


## Analysis Report
The script generates an HTML report (kdump_analysis_report.html) containing detailed analysis results.

![image](https://github.com/user-attachments/assets/0c83956f-064b-4b78-bbe5-b8b774371bb6)


## Installation
Clone the repository.
   
`$ git clone https://github.com/FrankZhu888/AnalyzeKdump.git`

`$ cd AnalyzeKdump`

Ensure dependencies are installed.
   
`$ sudo dnf install -y crash python3`

`$ sudo debuginfo-install kernel`

Run the script with appropriate arguments.

## Notes
Ensure the vmcore and vmlinux files match the crashed kernel version.
The script requires root privileges to install dependencies and access vmcore files.

## Support Contact

For issues or questions, contact:

Frank Zhu [frz@microsoft.com](mailto:frz@microsoft.com)

Microsoft Azure Linux Escalation Team
