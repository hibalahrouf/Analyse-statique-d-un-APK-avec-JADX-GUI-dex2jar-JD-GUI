
# Rapport d'analyse statique — UnCrackable Level 1

## Informations générales

- **Date d'analyse :** 01/03/2026  
- **Analyste :** Hiba  
- **Machine hôte :** Windows 10  
- **Émulateur :** Pixel 6 — Android 16 (API 36, Google APIs x86_64)  
- **APK analysé :** `UnCrackable-Level1.apk`  
- **Taille :** 66,651 bytes  
- **SHA-256 :** 1DA8BF57D266109F9A07C01BF7111A1975CE01F190B9D914BCD3AE3DBEF96F21  
- **Provenance :** OWASP UnCrackable Level 1 fourni dans le cadre du cours  
- **Signature :** Certificat OWASP (SHA256withRSA, clé 2048 bits)


## Task 1 — Verification of APK

### APK Size
![APK Size](images/1.png)

### ZIP Header Verification
![ZIP Header](images/2.png)

### APK File Structure
![APK Structure](images/3.png)

### SHA256 Hash
![SHA256](images/4.png)

### APK Signature
![Signature](images/5.png)
## Task 3 — Analyse du manifeste (JADX)

### Informations extraites
- **Package :** `owasp.mstg.uncrackable1`
- **Version :** 1.0 (versionCode = 1)
- **minSdkVersion :** 19
- **targetSdkVersion :** 28

### Permissions demandées
- Aucune permission déclarée dans le manifest.

### Composants identifiés
- **Activity principale :** `sg.vantagepoint.uncrackable1.MainActivity` (MAIN/LAUNCHER)

### Composants exportés / exposition
- Aucun attribut `android:exported` n'est défini dans le manifest.
- L’activité principale contient un `intent-filter` MAIN/LAUNCHER (exposition attendue pour lancer l’application).

### Configurations sensibles
- `android:debuggable="true"` : absent
- `android:usesCleartextTraffic="true"` : absent
- `android:allowBackup="true"` : **présent** (à vérifier selon les données stockées)

### Captures
- ![JADX overview](images/6.png)
- ![AndroidManifest](images/7.png)

## Task 4 — Recherche de chaînes sensibles (JADX)

### Résultats principaux (observations)

1. **`http` — RAS (faible)**
   - Résultat : uniquement `http://schemas.android.com/apk/res/android` (namespace Android XML)
   - Interprétation : ce n’est pas un endpoint réseau.
   - **Risque : Faible**
   - Preuve : ![http](images/8.png)

2. **Texte UI lié au “secret” (faible)**
   - Résultat : `res/values/strings.xml` → `"Enter the Secret String"`
   - Interprétation : texte d’interface, non sensible.
   - **Risque : Faible**
   **Crypto potentiellement faible : AES/ECB (moyen)**
   - Référence à `SecretKeySpec` et à l’algorithme `"AES/ECB/PKCS7Padding"`
   - Localisation : `sg.vantagepoint.a.a` → `a(byte[] bArr, byte[] bArr2)`
   - Interprétation : ECB est une mauvaise pratique cryptographique (absence d’IV, motifs détectables).
   - **Risque : Moyen**
   - **Remédiation :** préférer AES-GCM ou AES-CBC avec IV aléatoire + authentification.
   **Chaîne en clair liée à la validation du “secret” (moyen)**
   - Résultat : `"This is the correct secret."`
   - Localisation : `sg.vantagepoint.uncrackable1.MainActivity` (méthode `verify(...)` ou code associé)
   - Interprétation : logique/secret potentiellement exposé en clair dans le code.
   - **Risque : Moyen**
   - **Remédiation :** éviter les secrets en dur ; déplacer côté serveur/Keystore selon besoin.
   - Preuve : ![secret_search](images/11.png)

3. **Indicateur debug en clair (faible)**
   - Résultat : `"App is debuggable!"`
   - Localisation : `sg.vantagepoint.uncrackable1.MainActivity#onCreate(Bundle)`
   - Interprétation : message explicite lié à un contrôle anti-debug côté client.
   - **Risque : Faible**
   - **Remédiation :** retirer/limiter les messages debug explicites en production.
   - Preuve : ![mainactivity_code](images/14.png)
4. **Détection de build “test-keys” (faible à moyen)**
   - Résultat : `str.contains("test-keys")`
   - Interprétation : check d’environnement/dev build tags.
   - **Risque : Faible à Moyen**
   - **Remédiation :** éviter les checks fragiles côté client, renforcer le pipeline de build/CI et contrôles adaptés au contexte.
   - Preuve : ![key](images/17.png)

5. **Indices de détection root (faible à moyen)**
   - Résultats : chemins/strings type `/dev/...superuser...` et références `su_daemon`
   - Interprétation : signatures de détection root/environnement.
   - **Risque : Faible à Moyen**
   - **Remédiation :** limiter les messages explicites, compléter par mécanismes adaptés (selon contexte).
   - Preuve : ![dev](images/18.png)

### Preuves “RAS” (0 résultats)
- `https` : ![https_0](images/9.png)
- `password` : ![password_0](images/10.png)
- `token` : ![token_0](images/12.png)
- `api_key` : ![api_key_0](images/13.png)
- `staging` : ![staging_0](images/15.png)
- `firebase` : ![firebase_0](images/16.png)

### Preuves (contexte code)
- Crypto (AES/ECB) : ![crypto_code](images/19.png)
- MainActivity (root/debug checks) : ![mainactivity_code](images/20.png)
