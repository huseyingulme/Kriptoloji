# 🔐 Kriptoloji Projesi - Detaylı Açıklama

## 📋 Projenin Amacı

Bu proje, **gerçek hayattaki güvenli sistemlerin çalışma mantığını** simüle eden bir kriptoloji uygulamasıdır. Kullanıcılar metin, resim, ses veya video gibi verileri farklı şifreleme algoritmaları kullanarak şifreleyebilir veya çözebilir.

### 🎯 Temel Özellikler

- ✅ **Client-Server Mimarisi**: İki farklı bilgisayar arasında çalışabilir
- ✅ **Server Tarafında Şifreleme**: Tüm işlemler server'da yapılır (güvenlik için)
- ✅ **Çoklu Algoritma Desteği**: Caesar, Vigenere, Hill, AES, DES ve daha fazlası
- ✅ **Dosya Desteği**: Metin, resim, ses, video dosyaları işlenebilir
- ✅ **Grafik Arayüz**: Kullanıcı dostu Tkinter arayüzü

---

## 🏗️ Proje Yapısı

```
Kriptoloji/
├── client/              # Client (Kullanıcı) tarafı
│   ├── gui/            # Grafik arayüz
│   ├── network/        # Server bağlantı kodları
│   └── file/           # Dosya yönetimi
│
├── server/             # Server (Sunucu) tarafı
│   ├── network/        # Client bağlantılarını yöneten kodlar
│   ├── processing/     # Şifreleme işlemlerini yöneten kodlar
│   └── algorithms/     # Şifreleme algoritmaları
│
├── shared/             # Ortak kullanılan kodlar
│   └── utils.py        # Yardımcı fonksiyonlar
│
└── gui/                # Alternatif GUI (launcher için)
```

---

## 🔄 İşlem Akışı

### 1️⃣ **Şifreleme İşlemi**

```
Kullanıcı (Client)                    Server
     │                                    │
     │  1. Veri + Algoritma + Anahtar    │
     │───────────────────────────────────>│
     │                                    │
     │                                    │ 2. ProcessingManager
     │                                    │    algoritmayı seçer
     │                                    │
     │                                    │ 3. Şifreleme işlemi
     │                                    │    yapılır (SERVER'DA!)
     │                                    │
     │  4. Şifrelenmiş veri              │
     │<───────────────────────────────────│
     │                                    │
     │  5. Sonuç ekranda gösterilir      │
     │                                    │
```

### 2️⃣ **Deşifreleme İşlemi**

Aynı akış, sadece işlem tipi "DECRYPT" olur.

---

## 🔐 Şifreleme Algoritmaları

### Caesar Cipher
- **Açıklama**: Her harfi alfabede belirli bir sayı kadar kaydırır
- **Anahtar**: 1-999 arası sayı
- **Örnek**: Shift=3 → "HELLO" → "KHOOR"

### Vigenere Cipher
- **Açıklama**: Çoklu anahtar kullanan gelişmiş Caesar
- **Anahtar**: Kelime veya cümle
- **Örnek**: Key="KEY" → "HELLO" → "RIJVS"

### Hill Cipher
- **Açıklama**: Matris tabanlı şifreleme
- **Anahtar**: Matris
- **Özellik**: Güçlü şifreleme

### AES (Advanced Encryption Standard)
- **Açıklama**: Modern, güvenli şifreleme standardı
- **Anahtar**: 128, 192 veya 256 bit
- **Özellik**: Endüstri standardı

### DES (Data Encryption Standard)
- **Açıklama**: Eski şifreleme standardı
- **Anahtar**: 56 bit
- **Not**: Artık güvenli değil, eğitim amaçlı

---

## 💻 Kullanım

### Server'ı Başlatma

```bash
# Terminal 1 (Server PC)
python main.py server --host 0.0.0.0 --port 12345
```

veya

```bash
python launcher.py
# "Server Başlat" butonuna tıklayın
```

### Client'ı Başlatma

```bash
# Terminal 2 (Client PC veya aynı PC)
python main.py client
```

veya

```bash
python launcher.py
# "Client Başlat" butonuna tıklayın
```

### İki PC Arasında Kullanım

1. **Server PC**: Server'ı başlatın ve IP adresini not edin
2. **Client PC**: Client'ı başlatın ve server IP'sini girin
3. **Bağlan**: "Bağlan" butonuna tıklayın
4. **Şifrele**: Veriyi girin, algoritma seçin ve "İşlemi Başlat"a tıklayın

---

## 🔒 Güvenlik Notları

### ⚠️ ÖNEMLİ: Neden Server Tarafında Şifreleme?

1. **Güvenlik**: Client tarafı manipüle edilebilir, server tarafı daha güvenlidir
2. **Merkezi Yönetim**: Algoritmalar tek bir yerde yönetilir
3. **Gerçek Hayat**: Bankalar, WhatsApp, e-devlet hepsi böyle çalışır
4. **Kontrol**: Server, hangi algoritmaların kullanılabileceğini kontrol eder

### 📝 Notlar

- Bu proje **eğitim amaçlıdır**
- Gerçek üretim ortamında ek güvenlik önlemleri gerekir
- Şifreleme anahtarları güvenli bir şekilde saklanmalıdır
- Network trafiği şifrelenmelidir (HTTPS/TLS gibi)

---

## 🛠️ Teknik Detaylar

### Veri Paketleme

Tüm veriler `DataPacket` sınıfı ile paketlenir:

```python
packet = {
    'data': bytes,           # Şifrelenecek veri
    'type': 'ENCRYPT',       # İşlem tipi
    'metadata': {
        'algorithm': 'caesar',  # Algoritma adı
        'key': '3',            # Anahtar
        'timestamp': 1234567890
    }
}
```

### Büyük Dosyalar

1024 byte'dan büyük veriler otomatik olarak parçalara bölünür (chunking).

### Hata Yönetimi

- Bağlantı hataları otomatik yeniden deneme ile yönetilir
- Tüm hatalar loglanır
- Kullanıcıya anlaşılır hata mesajları gösterilir

---

## 📚 Kod Yapısı

### Client Tarafı

- **Client.py**: Server'a bağlanır ve istek gönderir
- **MainWindow.py**: Kullanıcı arayüzü
- **FileManager.py**: Dosya işlemleri

### Server Tarafı

- **Server.py**: Client bağlantılarını yönetir
- **ProcessingManager.py**: Şifreleme işlemlerini yönetir
- **Algorithms/**: Şifreleme algoritmaları

---

## 🎓 Öğrenme Hedefleri

Bu proje ile şunları öğrenebilirsiniz:

1. ✅ **Client-Server Mimarisi**: İki bilgisayar arası iletişim
2. ✅ **Socket Programlama**: TCP/IP bağlantıları
3. ✅ **Kriptoloji**: Farklı şifreleme algoritmaları
4. ✅ **Network Güvenliği**: Veri aktarımı ve güvenlik
5. ✅ **Python Programlama**: OOP, threading, GUI

---

## 📞 Destek

Sorularınız için:
- Kod içindeki yorumları okuyun
- Her dosyanın başındaki açıklamalara bakın
- İşlem adımları kod içinde detaylı olarak açıklanmıştır

---

**Not**: Bu proje, kriptoloji ve network programlama alanında pratik deneyim kazanmak için tasarlanmıştır.

