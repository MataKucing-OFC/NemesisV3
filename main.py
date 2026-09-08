#!/usr/bin/env python3
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

import os
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = PROJECT_ROOT / "result"
SETTINGS_PATH = PROJECT_ROOT / "settings.json"
RESULTS_DIR.mkdir(exist_ok=True)
os.chdir(PROJECT_ROOT)



def install_requirements():
    """
    Function to install the required Python packages.
    It checks if the necessary packages are installed and installs them if they are not found.
    """
    required_packages = {
        'requests': 'requests',
        'colorama': 'colorama',
        'ipaddress': 'ipaddress',
        'pyfiglet': 'pyfiglet',
        'ssl': 'ssl',
        'beautifulsoup4': 'bs4',
        'dnspython': 'dns',
        'multithreading': 'multithreading',
        'loguru': 'loguru'
    }

    # Iterating through each required package and checking for installation
    for package, import_name in required_packages.items():
        try:
            __import__(import_name)  # Check if the package is already installed
        except ImportError:
            # Install the missing package if not found
            print(f"[WAIT] Package '{package}' is not installed. Installing...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[OK] Package '{package}' installed successfully.")

# Run the install_requirements function to ensure necessary packages are installed
install_requirements()

from colorama import Fore, Style, Back, init
import pyfiglet

# Initialize colorama to automatically reset styles after each print
init(autoreset=True)



def clear_screen():
    """
    Function to clear the terminal screen based on the operating system.
    """
    os.system('cls' if os.name == 'nt' else 'clear')



def text_to_ascii_banner(text, font="doom", color=Fore.WHITE):
    """
    Converts text to an ASCII art banner using the pyfiglet library and applies color formatting.
    Args:
        text (str): The text to convert into ASCII art.
        font (str): The font style for the ASCII art (default is "doom").
        color (str): The color for the ASCII art text (default is white).
    Returns:
        str: The colored ASCII art banner.
    """
    try:
        ascii_banner = pyfiglet.figlet_format(text, font=font)
        colored_banner = f"{color}{ascii_banner}{Style.RESET_ALL}"
        return colored_banner
    except pyfiglet.FontNotFound:
        return "Font not found. Please choose a valid font."



def get_input(prompt, default=None):
    """
    Utility function to get user input with a prompt.
    Returns default if user does not provide input.
    """
    response = input(prompt + Style.BRIGHT).strip()
    print(Style.RESET_ALL)
    return response if response else default or ""


def cve_modules():
    """Return the CVE scripts available in this checkout."""
    return sorted(
        (path for path in (PROJECT_ROOT / "modules").glob("CVE-*.py")
         if path.is_file()),
        key=lambda path: path.name.lower(),
    )


def load_cve_settings():
    """Load the shared CVE launcher settings from settings.json."""
    try:
        with SETTINGS_PATH.open(encoding="utf-8") as settings_file:
            settings = json.load(settings_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("could not read settings.json: " + str(exc))

    required = ("target_list", "username", "password", "email", "thread")
    missing = [key for key in required if not settings.get(key)]
    if missing:
        raise RuntimeError("missing settings: " + ", ".join(missing))
    return settings


# These scripts support an output option; the launcher gives each result a
# predictable CVE-named file in result/.
CVE_OUTPUT_OPTIONS = {
    "CVE-2025-13486.py": ("-o", "--output"),
    "CVE-2025-14156.py": ("-o", "--output"),
    "CVE-2025-55182.py": ("-o", "--output"),
    "CVE-2026-0920.py": ("-o", "--output"),
    "CVE-2026-41940.py": ("--output",),
}


CVE_HELP = {
    "CVE-2025-11533.py": (
        "Domain-list interactive tool.",
        "Run it, enter a text file containing domains, then confirm at the prompt.",
    ),
    "CVE-2025-13486.py": (
        "Plugin detection and CVE-2025-13486 target tool.",
        "Use --url URL or --list FILE; see the script help for verification, "
        "user, password, thread, and output options.",
    ),
    "CVE-2025-14156.py": (
        "CVE-2025-14156 mass target tool.",
        "Use -u URL or -l FILE, with optional -t THREADS, -o OUTPUT, and --timeout SECONDS.",
    ),
    "CVE-2025-15030.py": (
        "Interactive CVE-2025-15030 target tool.",
        "Run it, then provide the target list file, requested password, and 1-50 threads.",
    ),
    "CVE-2025-55182.py": (
        "React2Shell CVE-2025-55182 mass scanning tool.",
        "Use its --help output to choose a URL/list input, command, workers, timeout, "
        "TLS, and output options.",
    ),
    "CVE-2025-6934.py": (
        "CVE-2025-6934 target tool.",
        "Required arguments include -u URL, -mail EMAIL, and -password PASSWORD; "
        "use -user USERNAME to override the default.",
    ),
    "CVE-2026-0920.py": (
        "CVE-2026-0920 WordPress target tool.",
        "Use -u URL or -f FILE with required -U USERNAME, -E EMAIL, and -P PASSWORD; "
        "see --help for worker, timeout, output, and confirmation options.",
    ),
    "CVE-2026-18366.py": (
        "CVE-2026-18366 Events Manager target tool.",
        "Use -l FILE (or provide targets interactively), with optional --workers and "
        "--timeout.",
    ),
    "CVE-2026-41940.py": (
        "CVE-2026-41940 cPanel/WHM target tool.",
        "Use its --help output to choose a URL/list input, optional password, "
        "--check-only, threads, timeout, and output.",
    ),
    "CVE-2026-60137-63030.py": (
        "WordPress CVE-2026-63030 and CVE-2026-60137 audit tool.",
        "Use required -l FILE, with optional -t THREADS, --timeout SECONDS, and --proxy URL.",
    ),
}


def show_cve_help(modules):
    """Display safe usage guidance for every CVE module without running scans."""
    print(Fore.LIGHTBLUE_EX + "\n  Nemesis CVE tools - usage help")
    print(Fore.WHITE + "  Help only; select a numbered tool to launch it.")
    for module_path in modules:
        purpose, fallback = CVE_HELP.get(
            module_path.name,
            ("CVE module.", "Run the tool with its documented arguments."),
        )
        print(Fore.LIGHTYELLOW_EX + "\n  " + module_path.stem)
        print(Fore.WHITE + "    Purpose: " + purpose)
        source = module_path.read_text(encoding="utf-8", errors="replace")
        if "argparse.ArgumentParser" in source:
            try:
                completed = subprocess.run(
                    [sys.executable, str(module_path), "--help"],
                    cwd=str(PROJECT_ROOT),
                    env=os.environ.copy(),
                    input="",
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                help_text = (completed.stdout or completed.stderr).strip()
            except (OSError, subprocess.TimeoutExpired) as exc:
                help_text = (
                    "Script help was unavailable (" + str(exc) + ").\n"
                    "Fallback guidance: " + fallback
                )
            if help_text:
                print(Fore.WHITE + "    Usage and arguments:")
                for line in help_text.splitlines():
                    print("      " + line)
            else:
                print(Fore.WHITE + "    Guidance: " + fallback)
        else:
            print(Fore.WHITE + "    Guidance: " + fallback)


LIST_TARGET_MODULES = {
    "CVE-2025-13486.py",
    "CVE-2025-14156.py",
    "CVE-2026-18366.py",
    "CVE-2026-60137-63030.py",
}

TARGET_OPTIONS = {
    "CVE-2025-13486.py": ("-l",),
    "CVE-2025-14156.py": ("-l",),
    "CVE-2025-55182.py": ("-l",),
    "CVE-2026-0920.py": ("-f",),
    "CVE-2026-18366.py": ("-l",),
    "CVE-2026-41940.py": ("--targets-file",),
    "CVE-2026-60137-63030.py": ("-l",),
}

SETTING_OPTIONS = {
    "username": {
        "CVE-2025-13486.py": ("--user",),
        "CVE-2025-6934.py": ("--username",),
        "CVE-2026-0920.py": ("--username",),
    },
    "password": {
        "CVE-2025-13486.py": ("--password",),
        "CVE-2025-6934.py": ("--newpassword",),
        "CVE-2026-0920.py": ("--password",),
        "CVE-2026-41940.py": ("--password",),
    },
    "email": {
        "CVE-2025-6934.py": ("--newmail",),
        "CVE-2026-0920.py": ("--email",),
    },
}

THREAD_OPTIONS = {
    "CVE-2025-13486.py": "-t",
    "CVE-2025-14156.py": "-t",
    "CVE-2025-55182.py": "-t",
    "CVE-2026-41940.py": "--threads",
    "CVE-2026-60137-63030.py": "-t",
}

INTERACTIVE_CVE_MODULES = {
    "CVE-2025-11533.py",
    "CVE-2025-15030.py",
}


def prepare_cve_target_arguments(arguments, module_name, settings):
    """Build CVE arguments from settings while preserving extra arguments."""
    prepared = list(arguments)
    url_options = {"-u", "--url"}

    target_options = TARGET_OPTIONS.get(module_name)
    if target_options:
        list_file = PROJECT_ROOT / settings["target_list"]
        if not list_file.is_file():
            raise FileNotFoundError(
                settings["target_list"] + " was not found in the NemesisToolz directory"
            )
        prepared = [target_options[0], str(list_file)] + prepared

    for setting_name, module_options in SETTING_OPTIONS.items():
        options = module_options.get(module_name)
        if options:
            prepared.extend((options[0], settings[setting_name]))

    thread_option = THREAD_OPTIONS.get(module_name)
    if thread_option:
        prepared.extend((thread_option, str(settings["thread"])))

    if module_name == "CVE-2025-6934.py":
        list_file = PROJECT_ROOT / settings["target_list"]
        target = next(
            (
                line.strip()
                for line in list_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ),
            None,
        )
        if not target:
            raise ValueError(settings["target_list"] + " does not contain a target")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        prepared.extend(("--url", target))
    return prepared


def launch_cve(module_path):
    """Launch one existing CVE entrypoint without invoking a shell."""
    print(Fore.LIGHTBLUE_EX + "\n  Selected: " + module_path.name)
    # Launch immediately. Modules that need input retain their own entrypoint.
    arguments = []
    try:
        settings = load_cve_settings()
        arguments = prepare_cve_target_arguments(
            arguments, module_path.name, settings
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(Fore.RED + "  Could not prepare CVE settings: " + str(exc))
        return

    output_options = CVE_OUTPUT_OPTIONS.get(module_path.name, ())
    if output_options and not any(
            argument in output_options
            or any(argument.startswith(option + "=")
                   for option in output_options)
            for argument in arguments):
        arguments.extend((output_options[0], str(RESULTS_DIR / module_path.stem)))
        # The scripts append their own extension where appropriate; .txt is a
        # safe default for the existing text result writers.
        arguments[-1] += ".txt"

    environment = os.environ.copy()
    environment["NEMESIS_RESULTS_DIR"] = str(RESULTS_DIR)
    command = [sys.executable, str(module_path)] + arguments
    input_data = None
    if module_path.name in INTERACTIVE_CVE_MODULES:
        if module_path.name == "CVE-2025-11533.py":
            input_data = "\n".join(
                (str(PROJECT_ROOT / settings["target_list"]), "y")
            ) + "\n"
        else:
            input_data = "\n".join(
                (
                    str(PROJECT_ROOT / settings["target_list"]),
                    settings["password"],
                    str(settings["thread"]),
                )
            ) + "\n"
    try:
        completed = subprocess.run(
            command,
            cwd=str(PROJECT_ROOT),
            env=environment,
            input=input_data,
            text=True,
            check=False,
        )
        if completed.returncode:
            print(Fore.YELLOW + "\n  CVE module exited with status "
                  + str(completed.returncode) + ".")
    except OSError as exc:
        print(Fore.RED + "\n  Could not launch CVE module: " + str(exc))


def cve_menu():
    """Interactive launcher for the standalone CVE modules."""
    while True:
        clear_screen()
        print(Fore.LIGHTBLUE_EX + Style.BRIGHT + "CVE tools")
        modules = cve_modules()
        if not modules:
            print(Fore.YELLOW + "No CVE modules found.")
            input(Fore.YELLOW + "\nPress Enter to return...")
            return
        for index, module_path in enumerate(modules, 1):
            print(Fore.LIGHTYELLOW_EX + "{0}. {1}".format(
                index, module_path.stem))
        print(Fore.LIGHTYELLOW_EX + "0. Back")
        choice = get_input(Fore.CYAN + "\nSelect tool: ").strip()
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(modules):
            print(Fore.RED + "\nInvalid selection.")
            input(Fore.YELLOW + "Press Enter to continue...")
            continue
        launch_cve(modules[int(choice) - 1])
        input(Fore.YELLOW + "\nPress Enter to return to CVE tools...")



def banner():
    """
    Displays the banner for the toolkit with ASCII art and basic information about the project.
    """
    clear_screen()
    print(text_to_ascii_banner("NEMESIS", font="doom", color=Style.BRIGHT + Fore.MAGENTA))
    print(Fore.LIGHTMAGENTA_EX + Style.BRIGHT + "  MataKucing | Team Nemesis")
    print(Fore.LIGHTBLUE_EX + "  Output: " + Style.BRIGHT + str(RESULTS_DIR))
    print(Fore.WHITE + Style.DIM + "\n  Security research toolkit | Use only with permission")
    print(Style.RESET_ALL)



def main_menu():
    """
    Main menu loop for the Nemesis toolkit, allowing users to select different scanning and OSINT options.
    Each option will run a specific scan or tool from the 'modules' directory.
    """
    while True:
        banner()
        print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "+-- Nemesis Operations ----------------------------+")
        print(Fore.LIGHTYELLOW_EX + "| [1] Host Scanner          [6] TXT Toolkit       |")
        print(Fore.LIGHTYELLOW_EX + "| [2] Subdomains Scanner    [7] Open Ports        |")
        print(Fore.LIGHTYELLOW_EX + "| [3] IP Scanner            [8] DNS Records       |")
        print(Fore.LIGHTYELLOW_EX + "| [4] Subdomain Finder      [9] OSINT             |")
        print(Fore.LIGHTYELLOW_EX + "| [5] Reverse IP            [10] Help             |")
        print(Fore.LIGHTYELLOW_EX + "| [11] CVE Tools                                  |")
        print(Fore.LIGHTRED_EX + Style.BRIGHT + "| [0] Exit                                        |")
        print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "+--------------------------------------------------+" + Style.RESET_ALL)

        # Get the user's choice
        choice = get_input(Fore.CYAN + "\n  Select an operation (0-11): ").strip()


        if choice == '1':
            clear_screen()
            print(text_to_ascii_banner("HOST Scanner", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.host_scanner as host_scanner
            host_scanner.bugscanner_main()
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "2":
            clear_screen()
            print(text_to_ascii_banner("SUBDOMAIN Scanner", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.sub_scan as sub_scan
            hosts, ports, output_file, threads, method = sub_scan.get1_scan_inputs()
            if hosts is None:
                continue
            sub_scan.perform1_scan(hosts, ports, output_file, threads, method)
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "3":
            clear_screen()
            print(text_to_ascii_banner("IP Scanner", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.ip_scan as ip_scan
            hosts, ports, output_file, threads, method = ip_scan.get2_scan_inputs()

            if hosts is None:
                continue

            ip_scan.perform2_scan(hosts, ports, output_file, threads, method)
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "4":
            clear_screen()
            print(text_to_ascii_banner("Subfinder ", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.sub_finder as sub_finder
            sub_finder.find_subdomains()
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "5":
            clear_screen()
            print(text_to_ascii_banner("IP LookUP ", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.ip_lookup as ip_lookup
            ip_lookup.Ip_lockup_menu()
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "9":
            clear_screen()
            print(text_to_ascii_banner("OSINT ", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.osint as osint
            osint.osint_main()
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "6":
            clear_screen()
            print(text_to_ascii_banner("TXT Toolkit", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.txt_toolkit as txt_toolkit
            txt_toolkit.txt_toolkit_main_menu()
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "7":
            clear_screen()
            print(text_to_ascii_banner("Open Port ", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            import modules.open_port as open_port
            open_port.open_port_checker()
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "8":
            clear_screen()
            print(text_to_ascii_banner("DNS Records ", font="doom", color=Style.BRIGHT+Fore.MAGENTA))
            domain = get_input(Fore.CYAN + " âžœ  Enter a domain to perform NSLOOKUP: ").strip()
            import modules.dns_info as dns_info
            dns_info.nslookup(domain)
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "10":
            clear_screen()
            import modules.script_help as script_help
            script_help.show_help()
            input(Fore.YELLOW + "\n Press Enter to return to the main menu...")

        elif choice == "11":
            cve_menu()

        elif choice == "0":
            print(Fore.RED + Style.BRIGHT + "\nðŸ”´ Shutting down Nemesis. See you next time!")
            sys.exit()

        else:
            print(Fore.RED + Style.BRIGHT + "\nâš ï¸ Invalid choice. Please select a valid option.")
            input(Fore.YELLOW + Style.BRIGHT + "\n Press Enter to return to the main menu...")
            continue



# Run the menu
if __name__ == "__main__":
    main_menu()
