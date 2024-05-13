import psutil
import re
from typing import Union
from pathlib import Path

"""
Title: Detect and Mitigation Program.
Author: Samuel Timothy Ashman.
Date Last Modified: 25/04/2024.
Description: 
When the program is ran, it will check your system processes.
Filter down/flag unknown/suspicous processes.
Inspect each flagged process.
Terminate each flagged process if required.

Dependencies:
The 'psutil' module is required to run nearly every aspect of this program.
"""

suspicous_processes = []

filter_proc = []

new_sus = []

ports = [
    "port=80",
    "port=20",
    "port=443",
    "port=25",
    "port=143",
    "port=23",
    "port=22",
    "port=110",
    "port=2049",
    "port=27035",
]

common_windows_processes = [
    "SystemSettingsBroker.exe",
    "svchost.exe",
    "services.exe",
    "wininit.exe",
    "jhi_service.exe",
    "OneApp.IGCC.WinService.exe",
    "SupportAssistAgent.exe",
    "spoolsv.exe",
    "WUDFHost.exe",
    "lsass.exe",
    "System Idle Process",
    "System",
    "Registry",
    "RuntimeBroker.exe",
    "conhost.exe",
    "SecurityHealthSystray.exe",
    "ApplicationFrameHost.exe",
    "DDVCollectorSvcApi.exe",
    "OfficeClickToRun.exe",
    "SearchProtocolHost.exe",
    "WidgetService.exe",
    "SearchHost.exe",
    "PhoneExperienceHost.exe",
    "SecurityHealthService.exe",
    "csrss.exe",
    "SystemSettings.exe",
    "SDXHelper.exe",
    "UserOOBEBroker.exe",
    "dwm.exe",
    "winlogon.exe",
    "ipf",
    "SmartByteAnalyticsService.exe",
    "SmartByteNetworkService.exe",
    "dllhost.exe",
    "RuntimeBroker.exe",
    "AggregatorHost.exe",
    "fontdrvhost.exe",
    "SearchIndexer.exe",
    "smss.exe",
    "WmiPrvSE.exe",
    "TitanCoreSubAgent.exe",
    "unsecapp.exe",
    "ServiceShell.exe",
    "IntelConnectivityNetworkService.exe",
    "browser_assistant.exe",
    "sihost.exe",
    "Widgets.exe",
    "ctfmon.exe",
    "taskhostw.exe",
    "DDVDataCollector.exe",
    "vmcompute.exe",
    "msdtc.exe",
    "DDVRulesProcessor.exe",
    "ipf_uf.exe",
    "ipf_helper.exe",
    "LsaIso.exe",
    "IDBWMService.exe",
    "IntelConnect.exe",
    "IntelConnectService.exe",
    "IDBWM.exe",
    "IDBWMService.exe",
    "OneDrive.exe",
    "WMIRegistrationService.exe",
    "RstMwService.exe",
    "MsMpEng.exe",
    "RtkBtManServ.exe",
    "IntelCpHDCPSvc.exe",
    "MemCompression",
    "ShellExperienceHost.exe",
    "DellSupportAssistRemedationService.exe",
    "steamwebhelper.exe",
    "opera.exe",
    "Dell.TechHub.Diagnostics.SubAgent.exe",
    "Dell.TechHub.exe",
    "Dell.Customer.Connect.SubAgent.exe",
    "Dell.CoreServices.Client.exe",
    "steam.exe",
    "wslservice.exe",
    "WavesSvc64.exe",
    "Dell.D3.WinSvc.exe",
    "explorer.exe",
    "Dell.DCF.UA.Bradbury.API.SubAgent.exe",
    "Dell.UCA.Systray.exe",
    "StartMenuExperienceHost.exe",
    "NisSrv.exe",
    "Dell.UCA.Manager.exe",
    "steamservice.exe",
    "Dell.Optimizer.DthProxy.exe",
    "opera_crashreporter.exe",
    "DellOptimizer.exe",
    "Dell.TechHub.DataManager.SubAgent.exe",
    "WavesAudioService.exe",
    "WavesSysSvc64.exe",
    "Dell.TechHub.Analytics.SubAgent.exe",
    "OverwolfBrowser.exe",
    "XboxPcAppFT.exe",
    "IGCCTray.exe",
    "OverwolfHelper.exe",
    "Dell.TechHub.Instrumentation.UserProcess.exe",
    "texmaker.exe",
    "OverwolfHelper64.exe",
    "gamingservices.exe",
    "gamingservicesnet.exe",
    "Dell.TechHub.Instrumentation.SubAgent.exe",
    "IGCC.exe",
    "Overwolf.exe",
    "SecurityHealthHost.exe",
    "SecHealthUI.exe",
    "OpenConsole.exe",
    "powershell.exe",
    "python3.12.exe",
    "python.exe",
    "WindowsTerminal.exe",
    "audiodg.exe",
    "cmd.exe",
    "smartscreen.exe",
]


"""
    Check network connections and ports for processes.
 
    Args:
        proc (Process): A System Process.
 
    Returns:
        Process: Process (filter_proc).
    """


def filter_ports(filter_proc):
    global suspicous_processes
    filtered_ports = []
    for proc in psutil.net_connections(kind="tcp") or psutil.net_connections(
        kind="udp"
    ):
        if proc.status in ["ESTABLISHED"]:
            convert = str(proc.raddr)
            split = convert.split(",")[1]
            m = re.search(r"port=\w+", split)
            found = m.group()

            if found in ports:
                if proc.pid == filter_proc:
                    suspicous_processes.append(filter_proc)
                    return filter_proc


def file_exists_in_directories(
    directory_path: Union[str, Path],
    filename: str,
) -> bool:
    return (
        len([file for file in Path(directory_path).rglob(filename) if file.is_file()])
        > 0
    )


def filter_cpu(proc):
    global suspicous_processes
    curr_cpu_percent = proc.cpu_percent()
    if proc.info["status"] in ["running"]:
        if curr_cpu_percent > 10:
            suspicous_processes.append(proc.info["pid"])
            return proc.info["pid"]


def filter_disk(proc):
    global suspicous_processes
    if proc.info["status"] in ["running"]:
        if proc.info["name"] not in common_windows_processes:
            io_counters = proc.io_counters()
            disk_usage_process = io_counters[2] + io_counters[3]
            disk_io_counter = psutil.disk_io_counters()
            disk_total = disk_io_counter[2] + disk_io_counter[3]
            disk_percent = disk_usage_process / disk_total * 100
            if disk_percent > 10:
                suspicous_processes.append(proc.info["pid"])
                return proc.info["pid"]


"""
    Filter by username on the system.
 
    Args:
        proc (Process): A System Process.
 
    Returns:
        int: Process PID.
    """


def filter_user(proc):
    curr_user = proc.username
    if proc.info["status"] in ["running"]:
        if curr_user not in ["SYSTEM", "SA\\SA"]:
            if curr_user not in ["None"] and not None:
                pid = filter_processes(proc)
                if pid is not None:
                    suspicous_processes.append(pid)
                    return proc.info["pid"]


"""
    Check common Keylogging system process names.
 
    Args:
        proc (Process): A System Process.
 
    Returns:
        int: Process PID.
    """


def filter_proc_name(proc):
    if proc.info["status"] in ["running"]:
        if proc.info["name"] in [
            "TextInputHost.exe",
            "WindowsTerminal.exe",
            "Microsoft Text Input Application",
            "cmd.exe",
        ]:
            text_proc = proc.info["name"]

            if (
                text_proc == "TextInputHost.exe"
                or "Microsoft Text Input Application"
                and file_exists_in_directories("C:/Windows/SystemApps/", text_proc)
            ):
                suspicous_processes.append(proc.info["pid"])
                return proc.info["pid"]
            elif text_proc == "WindowsTerminal.exe" and file_exists_in_directories(
                "C:/Program Files/WindowsApps/", text_proc
            ):
                suspicous_processes.append(proc.info["pid"])
                return proc.info["pid"]
            else:
                suspicous_processes.append(proc.info["pid"])
                return proc.info["pid"]


def filter_mem(proc):
    global suspicous_processes
    curr_mem_percent = proc.memory_percent()
    if proc.info["status"] in ["running"]:
        if proc.info["name"] not in common_windows_processes:
            if curr_mem_percent <= 6 and curr_mem_percent > 2:
                print(
                    "Current Memory Percentage for:",
                    proc.info["name"] + "\nPercentage:",
                    proc.memory_percent(),
                )
            elif curr_mem_percent > 10:
                suspicous_processes.append(proc.info["pid"])
                return proc.info["pid"]


def filter_processes(proc):
    global suspicous_processes
    if proc.info["status"] in ["running"]:
        if proc.info["name"] not in common_windows_processes:
            return proc


"""
    Filter if a windows process is associated inside the SYSTEM32 directory.
 
    Args:
        proc (Process): A System Process.
 
    Returns:
        int: Process PID.
    """


def adv_filter(proc):
    global suspicous_processes
    if proc.info["status"] in ["running"]:
        proc_names = proc.info["name"]
        if not file_exists_in_directories(
            "C:/Windows/System32/", proc_names
        ) and not file_exists_in_directories("C:/WINDOWS/system32", proc_names):
            if proc.info["name"] in common_windows_processes:
                suspicous_processes.append(proc.info["pid"])
                return proc.info["pid"]


"""
    Filter a process by its parent/children processes.
 
    Args:
        proc (Process): A System Process.
 
    Returns:
        int: Process PID.
    """


def parent_child_filter(proc):
    global suspicous_processes
    if proc.info["status"] in ["running"]:
        convert = str(proc.parent)
        split = convert.split(",")[1]
        parent_process = split.strip().replace("name='", "").replace("'", "")

        convert = str(proc.children)
        split = convert.split(",")[1]
        child_process = split.strip().replace("name='", "").replace("'", "")

        if (
            proc.info["name"] != parent_process
            and proc.info["name"] in common_windows_processes
        ):
            suspicous_processes.append(proc.info["pid"])

        if (
            proc.info["name"] != child_process
            and proc.info["name"] in common_windows_processes
        ):
            suspicous_processes.append(proc.info["pid"])
            return proc.info["pid"]


def sus_proc_filter():
    global new_sus
    sus = list(set(suspicous_processes))
    unique_names = set()
    for sus_proc in sus:
        if (
            sus_proc is not None
            and sus_proc.info["name"] not in common_windows_processes
            and sus_proc.info["name"] not in unique_names
        ):
            unique_names.add(sus_proc.info["name"])
            new_sus.append(sus_proc.pid)


"""
    Inspect all processes flagged as suspicous.
 
    Args:
        None.
 
    Returns:
        None.
    """


def inspect_processes():
    while True:
        try:
            print("List of Processes to inspect:\n", new_sus)

            print("\n Input Options:\n (Type Process PID). \n All. \n Cancel. \n")
            proc_input = input(
                "What processes would you like to inspect? (Separate by commas/spaces): "
            )

            if proc_input == "All" or proc_input == "all":
                term = []
                for proc in new_sus:
                    if psutil.pid_exists(proc) and proc in new_sus:
                        p = psutil.Process(proc)
                        print(p)
                        term.append(p)
                term_process(term)
            elif proc_input == "cancel" or proc_input == "Cancel":
                break
            else:
                proc_num = proc_input.replace(",", " ").split()
                proc_num = [int(process) for process in proc_num]
                print("\nProcess/'s:\n")
                for proc in proc_num:
                    if psutil.pid_exists(proc) and proc in new_sus:
                        p = psutil.Process(proc)
                        term_process(p)
            break
        except ValueError or NameError as e:
            print("Invalid input.")
        except KeyboardInterrupt as e:
            print("Cancelling...")
            break


"""
    Terminate a process if needed that has been inspected.
 
    Args:
        proc (Process): A System Process.
 
    Returns:
        None.
    """


def term_process(proc):
    if type(proc) is list:
        for term_proc in proc:
            proc_input = input(
                "Would you like to terminate " + str(term_proc.name) + "? (Yes or No)\n"
            )
            if proc_input == "Yes" or proc_input == "yes":
                print("Process ", term_proc.name, "is being terminated...\n")
                term_proc.terminate
                term_proc.wait
            elif proc_input == "No" or proc_input == "no":
                print("Process ", term_proc.name, "is not being terminated...\n")
            else:
                print("Invalid Input!")
                term_process(proc)
    else:
        proc_input = input(
            "Would you like to terminate " + str(proc.name) + "? (Yes or No)\n"
        )
        if proc_input == "Yes" or proc_input == "yes":
            print("Process ", proc.name, "is being terminated...\n")
            proc.terminate
            proc.wait
        elif proc_input == "No" or proc_input == "no":
            print("Process ", proc.name, "is not being terminated...\n")
        else:
            print("Invalid Input!")
            term_process(proc)


def basic_filter():
    print("Running Basic Filtering...")
    for proc in psutil.process_iter(["pid", "name", "status", "username"]):
        filter_proc = filter_processes(proc)

        if filter_proc is not None:
            filter_ports(filter_proc)
            filter_mem(filter_proc)
            filter_cpu(filter_proc)
            filter_disk(filter_proc)


def advanced_filter():
    print("Running Advanced Filtering...")
    for proc in psutil.process_iter(["pid", "name", "status", "username"]):
        filter_proc = filter_processes(proc)

        if filter_proc is not None:
            parent_child_filter(filter_proc)
            adv_filter(filter_proc)
            filter_user(filter_proc)


def start_up():
    while True:
        try:
            print(
                "Welcome to the Detection and Mitigation Program!\n \n What filtering would you like to run?\n"
            )

            print(
                "Filter Options: \n Basic Filering (basic) \n Advanced Filtering (advanced) \n All (all) \n Cancel (cancel) \n"
            )
            proc_input = input("Enter input here: ")

            if (
                proc_input == "basic"
                or proc_input == "Basic Filering"
                or proc_input == "basic filtering"
            ):
                basic_filter()
                sus_proc_filter()
                if new_sus is not None and new_sus != []:
                    print("Running Inspection of Processes...\n")
                    inspect_processes()
                else:
                    print("There is no Suspicous Processes from Basic Filtering... \n")

            elif (
                proc_input == "advanced"
                or proc_input == "Advanced Filtering"
                or proc_input == "advanced filtering"
            ):
                advanced_filter()
                sus_proc_filter()
                if new_sus is not None and new_sus != []:
                    print("Running Inspection of Processes...\n")
                    inspect_processes()
                else:
                    print("There is no Suspicous Processes from Advanced Filtering...")
            elif proc_input == "All" or proc_input == "all":
                basic_filter()
                print("After Basic Filtering Sus Processes:", suspicous_processes, "\n")
                advanced_filter()
                sus_proc_filter()
                print("After Advanced Filtering Sus Processes:", new_sus, "\n")
                if new_sus is not None and new_sus != []:
                    print("Running Inspection of Processes...\n")
                    inspect_processes()
                else:
                    print(
                        "There is no Suspicous Processes from All Filtering Functions..."
                    )
            elif proc_input == "Cancel" or proc_input == "cancel":
                break
            break
        except ValueError or NameError as e:
            print("Invalid input.")
        except KeyboardInterrupt as e:
            print("Cancelling...")
            break


if __name__ == "__main__":
    start_up()
