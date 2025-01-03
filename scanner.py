import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import re

def url_scan():
    while True:
        try:
            # Başlangıç URL'sini belirleyin
            start_url = input("Enter the target URL (e.g., http://testphp.vulnweb.com): ")
            
            # DNS adını kontrol et
            if not re.match(r'^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})', start_url):
                print("[!] Please enter a valid DNS name with http or https.")
                continue

            # Kullanıcıdan doğru URL alındığında döngüden çık
            break
        except(KeyboardInterrupt, EOFError):
            print("\n[!] Scan cancelled by user. Exiting...")
            return
    print("\n[*]Scanning url")
    # Gidilecek URL leri saklamak için kuyruk oluşturun ve başlangıç URL'sini ekleyin
    queue = deque([start_url])
    # Ziyaret edilen URL leri saklamak için bir set
    visited_urls = set()

    # Aynı alan adı altında kalmak için alan adını ayrıştırın
    domain_name = urlparse(start_url).netloc

    # Bulunan tüm URL'leri saklamak için bir set
    all_urls = set()

    try:
        # Kuyruktaki tüm URL'leri dolaş
        while queue:
            url = queue.popleft()
            # URL daha önce ziyaret edildiyse tekrar işlem yapma
            if url in visited_urls:
                continue
            
            # URL'yi ziyaret edilmiş olarak işaretle
            visited_urls.add(url)
            
            try:
                # Sayfayı indir
                response = requests.get(url, timeout=10)
                response.raise_for_status()  # Hata varsa atla
            except requests.RequestException:
                # Herhangi bir istek hatası durumunda atla
                continue

            # HTML içeriğini BeautifulSoup ile işle
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Sayfadaki tüm bağlantıları bul
            for link in soup.find_all("a"):
                href = link.get("href")
                if href:
                    # URL'yi tam URL haline getir
                    full_url = urljoin(url, href)
                    # Aynı alan adına ait olan ve ziyaret edilmemiş sayfaları ekle
                    if urlparse(full_url).netloc == domain_name and full_url not in visited_urls:
                        queue.append(full_url)
                        all_urls.add(full_url)

        # Tüm URL'leri yazdır
        print("\nBulunan URL'ler:")
        for url in all_urls:
            print(url)

    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user. Exiting...")

