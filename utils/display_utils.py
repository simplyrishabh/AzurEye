# utils/display_utils.py
from colorama import Fore, Style
from tabulate import tabulate

def print_banner():
    banner = f"""
{Fore.CYAN}  ___                 _____           {Style.RESET_ALL}
{Fore.CYAN} / _ \\               |  ___|          {Style.RESET_ALL}
{Fore.CYAN}/ /_\\ \\_____   _ _ __| |__ _   _  ___ {Style.RESET_ALL}
{Fore.CYAN}|  _  |_  / | | | '__|  __| | | |/ _ \\{Style.RESET_ALL}
{Fore.CYAN}| | | |/ /| |_| | |  | |__| |_| |  __/{Style.RESET_ALL}
{Fore.CYAN}\\_| |_/___|\\__,_|_|  \\____|\\__, |\\___|{Style.RESET_ALL}
{Fore.CYAN}                           __/ |     {Style.RESET_ALL}
{Fore.CYAN}                          |___/      {Style.RESET_ALL}
{Fore.YELLOW}(Written By: Rishabh Gupta){Style.RESET_ALL}
{Fore.YELLOW}Description: A tool written in Python that Reveals Azure Misconfiguration{Style.RESET_ALL}
{Fore.YELLOW}Hunting the cloud’s silent prey{Style.RESET_ALL}
"""
    print(banner)

def display_roles_table(principal_id, role_assignments):
    print(f"\n{Fore.YELLOW}Current User Principal ID: {principal_id}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Role Assignments:{Style.RESET_ALL}")
    table = [[assignment["roleDefinitionName"], assignment["scope"]] for assignment in role_assignments]
    print(tabulate(table, headers=["Role", "Scope"], tablefmt="grid"))

# Test it standalone
if __name__ == "__main__":
    print_banner()
