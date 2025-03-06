# AnalyzeKdump

## Description
`AnalyzeKdump` is a Python script designed to analyze Linux kdump vmcore files for diagnosing VM hangs and performance issues. It extracts critical information such as D-state processes, hung tasks, kernel logs, system performance metrics, and potential hung causes (e.g., memory pressure, CPU scheduling, I/O issues, and interrupt statistics). The results are presented in a concise HTML report, making it easy to identify root causes of system failures.

This tool is particularly useful for system administrators and support engineers working with Red Hat Enterprise Linux (RHEL) or similar distributions.

## Features
- Analyzes D-state processes with backtraces.
- Identifies hung tasks based on kernel log entries (e.g., "blocked for more than X seconds").
- Evaluates system performance metrics (sys, kmem).
- Detects potential hung causes (memory, CPU, I/O, interrupts).
- Generates an HTML report with detailed findings.

## Requirements
- Python 3.x
- `crash` utility (install via `dnf install crash`)
- `kernel-debuginfo` (install via `debuginfo-install kernel`)
- Root privileges for execution

## Usage
sudo python3 AnalyzeKdump.py --vmcore <vmcore_path> --vmlinux <vmlinux_path> [--output <output_html>]

## Example
sudo python3 AnalyzeKdump.py --vmcore /var/crash/127.0.0.1-2025-02-25-08:03:04/vmcore \
                              --vmlinux /usr/lib/debug/lib/modules/5.14.0-162.el9.x86_64/vmlinux \
                              --output report.html

## Output

An HTML report (default: kdump_analysis_report.html) containing analysis results.

## Installation

1. Clone the repository:
git clone https://github.com/FrankZhu888/AnalyzeKdump.git
cd AnalyzeKdump

2. Ensure dependencies are installed:
sudo dnf install -y crash python3
sudo debuginfo-install kernel

3. Run the script with appropriate arguments.

## Notes
Ensure the vmcore and vmlinux files match the crashed kernel version.
The script requires root privileges to install dependencies and access vmcore files.

## Support Contact

For issues or questions, contact:

Frank Zhu [frz@microsoft.com](mailto:frz@microsoft.com)

Microsoft Azure Linux Escalation Team
