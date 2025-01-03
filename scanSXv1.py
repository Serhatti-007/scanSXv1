import sys
import pyfiglet
from scanner import url_scan
from sqli import start_sqli
from xss import start_xss

def display_banner():
    #PyFiglet ile bir banner yazdırır
    banner = pyfiglet.figlet_format("scanSXv1")
    print(banner)
    print("Welcome!")
    print("=" * 50)
    
def main_menu():
    try:
        while True:
            display_banner()
            print("1. URL Scan")
            print("2. Sqli Scan")
            print("3. Xss Scan")
            print("4. Exit")

            choice = input("Select an option: ")

            if choice == "1":
                url_scan()
            elif choice == "2":
                start_sqli()
            elif choice == "3":
                start_xss()               
            elif choice == "4":
                print("Exiting...")
                sys.exit()    
            else:
                print("Invalid selection, please try again.")
    except (KeyboardInterrupt, EOFError):  # Ctrl+C ve Ctrl+Z için
        print("\n[!] User has been logged out. Goodbye!")
        sys.exit()

if __name__ == "__main__":
    main_menu()


