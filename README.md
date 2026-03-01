
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

  ## Task 5 — Conversion DEX → JAR (dex2jar)

### Installation
dex2jar (version 2.x) téléchargé depuis le dépôt officiel GitHub et installé dans `C:\Tools\dex-tools-2.x`.

![dex2jar_installed](images/21.png)

### Extraction des fichiers DEX
Extraction de `classes.dex` depuis l’APK.

![dex_extracted](images/22.png)

### Conversion DEX → JAR
Conversion réalisée avec `d2j-dex2jar.bat`.

![dex2jar_conversion](images/23.png)

### Vérification du fichier JAR
Le fichier `app.jar` a été généré avec succès.

![jar_created](images/24.png)

## Task 6 — Comparaison JADX vs JD-GUI

### Chargement dans JD-GUI
- Ouverture de `app.jar` généré par dex2jar dans JD-GUI.

![jdgui_open](images/25.png)
![jdgui_loaded](images/26.png)

### Classe comparée
Classe analysée dans les deux outils : `sg.vantagepoint.uncrackable1.MainActivity`

![compare](images/27.png)

### Différences notables (≥3)

1. **Gestion des ressources Android (R)**
   - JADX reconstruit correctement `R.layout` et `R.id` :
     - `setContentView(R.layout.activity_main)`
     - `findViewById(R.id.edit_text)`
   - JD-GUI affiche des IDs numériques :
     - `setContentView(2130903040)`
     - `findViewById(2130837505)`

2. **Contexte Android et style du code**
   - JADX produit un code plus “Android-friendly” (`new AlertDialog.Builder(this)`, `@Override` lisible).
   - JD-GUI ajoute souvent des casts explicites (`(Context)this`) et un style plus verbeux.

3. **Lisibilité / reconstruction**
   - JADX offre une lecture plus claire (structure, variables, références Android).
   - JD-GUI ressemble davantage à une reconstruction “bytecode Java”, avec variables génériques (`paramView`, `paramBundle`) et classes internes plus lourdes.

### Conclusion
Pour l’analyse statique d’un APK Android (manifest + ressources + code), **JADX** est plus adapté. **JD-GUI** reste utile comme vue alternative Java, notamment pour comparer la décompilation.

## Constats détaillés

### Constat #1 : Sauvegarde Android autorisée (allowBackup=true)
**Sévérité :** Faible à Moyenne  
**Description :** L’application autorise la sauvegarde Android via `android:allowBackup="true"`.  
**Localisation :** `AndroidManifest.xml`  
**Impact potentiel :** Si des données sensibles sont stockées localement, elles pourraient être incluses dans des sauvegardes système.  
**Remédiation recommandée :** Désactiver la sauvegarde (`android:allowBackup="false"`) ou sécuriser les données sensibles.

---

### Constat #2 : Utilisation d’un schéma cryptographique faible (AES/ECB)
**Sévérité :** Moyenne  
**Description :** Le code utilise `"AES/ECB/PKCS7Padding"`, un mode cryptographique considéré faible.  
**Localisation :** `sg.vantagepoint.a.a` → méthode `a(byte[] bArr, byte[] bArr2)`  
**Impact potentiel :** Le mode ECB ne protège pas contre l’analyse de motifs dans les données chiffrées.  
**Remédiation recommandée :** Utiliser AES-GCM ou AES-CBC avec IV aléatoire et authentification.

---

### Constat #3 : Présence d’une chaîne sensible en clair
**Sévérité :** Moyenne  
**Description :** La chaîne `"This is the correct secret."` est présente en clair dans le code.  
**Localisation :** `sg.vantagepoint.uncrackable1.MainActivity#verify(View)`  
**Impact potentiel :** Exposition de logique sensible directement dans le code client.  
**Remédiation recommandée :** Éviter les secrets en dur ; déplacer la logique sensible côté serveur si applicable.

---

### Constat #4 : Messages explicites liés au debug
**Sévérité :** Faible  
**Description :** L’application affiche le message `"App is debuggable!"` en cas de détection.  
**Localisation :** `MainActivity#onCreate(Bundle)`  
**Impact potentiel :** Les messages explicites peuvent révéler les mécanismes de protection.  
**Remédiation recommandée :** Limiter les messages debug en production.

---

### Constat #5 : Détection d’environnement (root / test-keys) côté client
**Sévérité :** Faible à Moyenne  
**Description :** Le code contient des vérifications de root et de build tags (`test-keys`).  
**Localisation :** `MainActivity#onCreate(Bundle)` et classes associées  
**Impact potentiel :** Les contrôles côté client peuvent être contournés.  
**Remédiation recommandée :** Compléter par des mécanismes adaptés selon le contexte (attestation, validation serveur).

## Résumé exécutif

Cette analyse statique de l’application **OWASP UnCrackable Level 1** a permis d’identifier plusieurs points de sécurité pertinents.

Les principales observations concernent :

1. L’utilisation d’un schéma cryptographique faible (AES en mode ECB).
2. La présence d’une chaîne sensible en clair dans le code (`"This is the correct secret."`).
3. Des mécanismes de détection root/debug implémentés uniquement côté client.

Aucune permission dangereuse, aucun token, ni clé API de production n’ont été identifiés.  
Cependant, les pratiques cryptographiques et l’exposition de logique sensible justifient une vigilance particulière.

### Niveau de risque global : **Moyen**

Des améliorations sont recommandées, notamment :
- Remplacement d’AES/ECB par AES-GCM ou AES-CBC avec IV sécurisé.
- Éviter les secrets en dur dans le code.
- Limiter les messages explicites liés aux contrôles de sécurité.
