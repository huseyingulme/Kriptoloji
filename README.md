# Kriptoloji Projesi - Şifreleme ve Çözme Sistemi

## Desteklenen Algoritmalar

1. **Caesar Cipher** - Kaydırma tabanlı şifreleme
2. **Vigenère Cipher** - Anahtar kelime tabanlı şifreleme
3. **Hill Cipher** - Matris tabanlı şifreleme (2x2, 3x3)
4. **Playfair Cipher** - 5x5 matris tabanlı çift karakter şifreleme
5. **Rail Fence Cipher** - Zikzak desen tabanlı aktarım şifreleme
6. **Columnar Transposition** - Sütunlu kaydırma tabanlı aktarım şifreleme
7. **Polybius Cipher** - 5x5 tablo tabanlı satır/sütun şifreleme

##  Desteklenen Dosya Formatları

- **Metin**: .txt, .md, .py, .js, .html, .css
- **Resim**: .png, .jpg, .jpeg, .gif, .bmp
- **Ses**: .wav, .mp3, .flac, .aac
- **Video**: .mp4, .avi, .mkv, .mov
- **Doküman**: .pdf, .doc, .docx

##  Kullanım

### Server'ı Başlatma
```bash
python main.py server --host localhost --port 12345
```

### Client'ı Başlatma
```bash
python main.py client
```

##  Kullanım Adımları

1. **Server'ı Başlatın**: `python main.py server`
2. **Client'ı Başlatın**: `python main.py client`
3. **Server Bağlantısı**: GUI'de server IP ve port girin, "Bağlan" butonuna tıklayın
4. **Algoritma Seçin**: Dropdown'dan istediğiniz algoritmayı seçin
5. **Anahtar Girin**: Algoritma türüne göre uygun anahtarı girin
6. **Metin/Dosya Yükleyin**: Metin girin veya dosya seçin
7. **Şifrele/Çöz**: İşlem tipini seçin ve "İşlemi Başlat" butonuna tıklayın
8. **Sonucu Görün**: Şifrelenmiş/çözülmüş veri sonuç alanında görünür

##  Algoritma Anahtar Formatları

- **Caesar**: 1-999 arası sayı (örn: 3)
- **Vigenere**: Alfabetik karakterler (örn: KEY)
- **Hill**: 2x2: 1,2,3,4 veya 3x3: 1,2,3,4,5,6,7,8,9
- **Playfair**: Anahtar kelime (J hariç, örn: MONARCHY)
- **Rail Fence**: Ray sayısı 2-10 arası (örn: 3)
- **Columnar**: Anahtar kelime (örn: KEYWORD)
- **Polybius**: Tablo düzeni anahtarı (opsiyonel)



