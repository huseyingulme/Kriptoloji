# KRİPTOGRAFİ VE AĞ GÜVENLİĞİ: İSTEMCİ-SUNUCU ŞİFRELEME SİSTEMİ ANALİZİ

**Öğrenci Bilgileri:**
- **Ad Soyad:** Hüseyin Bünyamin Gülme
- **Öğrenci No:** 439591
- **GitHub Deposu:** [https://github.com/huseyingulme/Kriptoloji](https://github.com/huseyingulme/Kriptoloji)

---

## 1. Giriş ve Proje Özeti
Bu çalışma, modern ağ güvenliği prensiplerini uygulamalı olarak anlamak amacıyla geliştirilen, simetrik ve asimetrik şifreleme yöntemlerini içeren kapsamlı bir istemci-sunucu yazılımıdır. Proje, temel olarak **AES-128**, **DES** ve **RSA** algoritmalarının hem kütüphane bazlı hem de manuel implementasyonlarını kullanarak ağ üzerinden güvenli veri iletimini gerçekleştirmeyi ve bu trafiği analiz etmeyi hedefler.

## 2. Sistem Mimarisi ve İstisnai Özellikler
Sistem, Python programlama dili ve Tkinter GUI kütüphanesi kullanılarak geliştirilmiştir. Yazılımın mimarisi üç ana katmandan oluşur:

### 2.1. İletişim Protokolü ve Paket Yapısı
İstemci ve sunucu arasındaki iletişim, güvenilir bir iletim kanalı olan TCP (Transmission Control Protocol) üzerinden sağlanır. Veriler ham şekilde değil, özel olarak tasarlanmış bir paket yapısıyla (`DataPacket`) gönderilir. Her paket, verinin boyutu, metadata (algoritma adı, işlem türü, zaman damgası vb.) ve asıl şifreli yükü içerir.

### 2.2. Merkezi İşlem Birimi (ProcessingManager)
Sunucu tarafında, tüm algoritmalar bir "Registry" yapısında tutulur. `ProcessingManager`, gelen paketteki metadata bilgisine bakarak uygun algoritma nesnesini dinamik olarak seçer. Bu sayede sisteme yeni bir şifreleme tekniği eklemek, ana kod yapısını bozmadan saniyeler içinde gerçekleştirilebilir.

### 2.3. Hibrit Şifreleme Modu
RSA algoritmasının yavaşlığı ve büyük verilerdeki limitleri göz önüne alınarak sisteme **Hibrit Şifreleme** desteği eklenmiştir. Bu çalışma modunda:
1.  Veri, istemci tarafında rastgele üretilen bir AES anahtarı ile çok hızlı bir şekilde şifrelenir.
2.  Bu rastgele AES anahtarı, sunucunun RSA Public Key'i ile şifrelenerek pakete eklenir.
3.  Sunucu, kendi Private Key'i ile anahtarı çözer ve ardından ana veri bloğunu deşifre eder.
Bu yaklaşım, RSA'nın güvenliği ile AES'in hızını birleştiren modern internet (HTTPS/TLS) protokolünün temelidir.

---

## 3. Algoritmaların Teknik Detayları ve Manuel Uygulamalar

### 3.1. AES-128 (Kütüphaneli ve Manuel)
AES, veri bloklarını 128 bitlik birimler halinde işler. Manuel implementasyonumuzda, her bir blok için **10Round** yapısı kurulmuştur.
-   **SubBytes:** Verinin S-Box tabloları üzerinden doğrusal olmayan değişimi.
-   **ShiftRows:** Matris satırlarının dairesel kaydırılması.
-   **MixColumns:** Sütunların matematiksel olarak karıştırılması (Matematiksel bir matris çarpımı).
-   **AddRoundKey:** Her turda anahtarın veriye XOR'lanması.

### 3.2. DES (Data Encryption Standard)
DES, Feistel yapısını kullanan 64 bitlik bir blok şifreleyicidir. Manuel kodlamada:
-   **Initial Permutation (IP):** Verinin başlangıçta yer değiştirilmesi.
-   **F-Function:** Sağ yarımdaki verinin anahtar parçasıyla XOR'lanması ve S-box genişletmelerine tabi tutulması.
-   **Key Schedule:** 64 bitlik anahtardan 16 farklı "alt anahtar" üretilmesi süreci bizzat kodlanmıştır.

### 3.3. RSA (Anahtar Dağıtımı ve Matematiksel Temel)
RSA, asimetrik şifrelemenin öncüsüdür. Projede RSA, büyük veriler yerine "Anahtar Dağıtımı" (Key Exchange) amacıyla kullanılmaktadır. RSA'nın güvenliği, `n = p * q` formülündeki `n` sayısını oluşturan devasal asal sayıları (`p` ve `q`) çarpanlarına ayırmanın zorluğuna dayanır. Raporda manuel kodlanmasa da, sistemde 1024 ve 2048 bitlik anahtarlarla başarılı testler gerçekleştirilmiştir.

---

## 4. Karşılaştırmalı Analiz

| Kriter | Simetrik (AES/DES) | Asimetrik (RSA) |
| :--- | :--- | :--- |
| **Hız** | Milisaniyeler altında (Çok hızlı). | Veri boyutu arttıkça ciddi performans kaybı. |
| **Kullanım** | Ana verinin şifrelenmesi. | Anahtar değişimi ve dijital imza. |
| **Kaynak Tüketimi** | Düşük CPU ve Bellek kullanımı. | Yüksek matematiksel işlem gücü gerektirir. |

**Manuel vs Kütüphane:** Kütüphane tabanlı şifreleme (PyCryptodome/Hazmat), donanım seviyesinde (AES-NI) optimizasyona sahiptir ve her zaman manuel çözümlerden daha hızlıdır. Manuel kodlama ise, algoritmanın perdesi arkasındaki matematiksel dehayı anlamak için eşsiz bir araçtır.

---

## 5. Wireshark Analizi ve Ağ Trafiği Bulguları

Geliştirilen uygulama üzerinden yapılan ağ dinleme testlerinde aşağıdaki bulgular elde edilmiştir:

1.  **Veri Gizliliği:** Wireshark paketi yakalandığında, TCP Payload (yük) kısmında "Merhaba" veya "Ödev Raporu" gibi açık metin ifadeler yerine `0x7a8f...` veya `bmt4cWt5ay...` gibi anlamsız Hex/Base64 dizileri görülmektedir. Bu, gizliliğin %100 sağlandığını gösterir.
2.  **Paket Boyutlarındaki RSA Etkisi:**
    *   İstemciden sunucuya gönderilen 10 byte'lık bir metin, AES ile şifrelendiğinde yaklaşık 16-32 byte'lık bir payload oluşturur.
    *   Aynı 10 byte, RSA (2048 bit) ile şifrelendiğinde paket boyutu bir anda 256 byte'a (anahtar uzunluğu) fırlar.
    *   **Nedeni:** RSA, veriyi her zaman anahtar boyutunun (modulus) bir parçası olarak matematiksel işleme aldığı için çıktı boyutu her zaman anahtar boyutuyla aynıdır. Bu, RSA'nın neden büyük veriler için uygun olmadığının en net kanıtıdır.

---

## 6. Sonuç ve Kişisel Değerlendirme

Bu proje, bir bilgisayar mühendisi adayı olarak şifrelemenin sadece bir metni bozmak değil, karmaşık bir anahtar yönetimi ve protokol tasarımı olduğunu anlamamı sağlamıştır. Manuel AES/DES implementasyonları ile algoritmaların "içine" girmek, kütüphane kullanırken yaptığımız işlemlerin ne kadar büyük bir emeği otomatize ettiğini göstermiştir. Ayrıca Wireshark analizi, teorik bilgilerimizi TCP/IP katmanlarında görselleştirmek adına projenin en kilit noktalarından birini oluşturmuştur.

**GitHub Repo:** https://github.com/huseyingulme/Kriptoloji

---
