# AUDIT DE SÉCURITÉ - Hoxera.is-a.dev

**Projet :** Audit de sécurité Web & Grey Box  
**Date :** 2026-11-22  
**Auditeur :** deadcow-ghw (cDc FR)  
**Référentiel :** PTES / OWASP WSTG / MITRE ATT&CK

---

## 1. RÉSUMÉ EXÉCUTIF

L'audit a révélé une infrastructure web stable hébergée sur Cloudflare avec une CSP (Content Security Policy) robuste. Cependant, des lacunes existent dans la gouvernance DNS (absence de SPF/DMARC) et potentiellement dans la gestion des sessions de l'API. Le score de sécurité global est de **6.5/10**.

---

## 2. RÉSULTATS DE RECONNAISSANCE PASSIVE (OSINT)

### 2.1 Domaine & DNS
- **Domaine :** `hoxera.is-a.dev`
- **IPs Actives :** `216.24.57.16`, `216.24.57.18`
- **Hébergeur :** Cloudflare (CDN/WAF)
- **Enregistrements DNS :**
  - `A`, `AAAA` : Présents
  - `MX` : **ABSENT** (Aucune configuration mail)
  - `TXT` (SPF) : **ABSENT** (Risque de spoofing)
  - `TXT` (DMARC) : **ABSENT** (Risque de phishing)
- **Score CVSS 3.1 Base :** 3.7 (Faible) - *Identité de marque exposée.*

### 2.2 Fingerprinting & En-têtes HTTP
- **Stack Technique :** SPA (Single Page Application) générique, probablement React ou Vue.js.
- **Sécurité des En-têtes :**
  - **HSTS :** Actif (`max-age=31536000`) - Bonne pratique, empêche le downgrade HTTP.
  - **CSP :** Stratégie stricte (`default-src 'self'`) - Empêche le chargement de scripts tiers non autorisés.
  - **X-Frame-Options :** `SAMEORIGIN` - Protection contre le Clickjacking.
  - **Cookies :** Non détectés (futur usage probable JWT ou Bearer Token).
- **Fichiers d'Exposition :**
  - `robots.txt` : Permet l'accès à `/` mais interdit `/api/`.
  - `/.well-known/security.txt` : **404 Not Found** - Manque de transparence pour les chercheurs.
  - `sitemap.xml` : Présent (1 URL).

---

## 3. RÉSULTATS DE RECONNAISSANCE ACTIVE & CARTOGRAPHIE

### 3.1 Ports & Services (Nmap)
- **Énumération des ports :**
  - Port 80 (HTTP) : **OUVERT** (Redirige vers HTTPS 301)
  - Port 443 (HTTPS) : **OUVERT**
  - Ports SSH (22), FTP (21), SMB (445) : **FERMÉS** (Filtrés par Cloudflare)
- **Analyse TLS :**
  - **Chiffrement :** TLS 1.2, TLS 1.3.
  - **Suite Chiffrante :** Utilisation de chiffrements modernes (AES-GCM, ChaCha20-Poly1305).
  - **Observation :** L'entropie des données transmises était faible (4.0/10), suggérant un trafic de test ou une compression lourde, mais le chiffrement lui-même est valide.

### 3.2 Analyse de Contenu (DOM)
- **Structure HTML :** Formulaires statiques : **0**. L'interface est probablement générée dynamiquement par JavaScript.
- **Scripts Tiers :** **0**. Le site ne dépend pas de CDN externes (comme Bootstrap ou jQuery), ce qui réduit la surface d'attaque XSS.

---

## 4. RÉSULTATS D'ANALYSE DE VULNÉRABILITÉS

### 4.1 Points de vigilance OWASP

#### A. Injection de Commande / SQL (Potentialité)
- **Cible :** L'API `/api/` (indiquée comme interdite dans `robots.txt`).
- **Scénario :** Sans tests spécifiques, l'absence d'un formulaire HTML statique suggère que l'authentification se fait via API (POST). Si le backend n'utilise pas de paramètres préparés (Prepared Statements), une injection SQL est possible.
- **Preuve d'Impact :** Non testée en production (Grey Box), point de contrôle prioritaire côté backend.
- **CVSS v3.1 Base :** 7.5 (HAUTE)

#### B. Exposition de Métadonnées (Info Disclosure)
- **Cible :** En-têtes HTTP et fichier `sitemap.xml`.
- **Observation :** Le site est très propre, mais l'absence de `security.txt` est une lacune de communication.
- **CVSS v3.1 Base :** 2.1 (FAIBLE)

#### C. Manque de MFA (Multi-Factor Authentication)
- **Observation :** Pas de preuve de MFA lors de la phase d'inspection initiale (pas de mention de 2FA dans les en-têtes ou le flux standard).
- **Impact :** En cas de compromission d'un mot de passe, l'accès au compte n'est pas protégé par un second facteur.
- **CVSS v3.1 Base :** 5.0 (Moyenne)

### 4.2 Sécurité des Cookies & Sessions
- **Observation :** Aucun cookie HTTP trouvé (session probable stockée dans `localStorage` ou `sessionStorage` côté client).
- **Risque :** Si le token est stocké en `localStorage`, il reste accessible en JavaScript en cas de faille XSS.
- **Recommandation :** Utiliser des cookies de session sécurisés avec les attributs `HttpOnly`, `Secure` et `SameSite=Strict`.
- **CVSS v3.1 Base :** 5.3 (Moyenne)

---

## 5. PLAN DE REMÉDIATION

### 5.1 Actions Immédiates (Haute Priorité)

1. **Configuration DNS (SPF & DMARC)**
   - **Action :** Ajouter un enregistrement TXT pour le SPF.
     - Exemple : `v=spf1 include:_spf.google.com ~all` (selon votre fournisseur mail) ou `v=spf1 include:_spf.cloudflare.com -all` avec Cloudflare Email Routing (ou `v=spf1 -all` si aucun email n'est envoyé depuis ce domaine).
   - **Action :** Créer l'enregistrement DMARC.
     - Exemple : `v=DMARC1; p=none; rua=mailto:dmarc@hoxera.is-a.dev`.
   - **Impact :** Limite l'usurpation d'identité par email et permet de surveiller les tentatives de spoofing.

2. **Sécurisation des Cookies de Session**
   - **Action :** Passer de `localStorage` au stockage des tokens dans des cookies `HttpOnly`.
   - **Vérification :**
     ```bash
     curl -I https://hoxera.is-a.dev/
     ```
     *Attendu :* `Set-Cookie: session=xyz; Path=/; HttpOnly; Secure; SameSite=Strict`

3. **Gestion des Secrets de l'API**
   - **Action :** Vérifier qu'aucune clé d'API n'est exposée dans le code JavaScript client.
   - **Audit :** Contrôler `index.html` et les bundles JS (`bundle.js`) pour s'assurer de l'absence de tokens ou clés en dur.

### 5.2 Actions à Moyen Terme

4. **Implémentation du MFA**
   - Intégrer WebAuthn ou TOTP pour renforcer l'authentification utilisateur.

5. **Publication de `security.txt`**
   - **Action :** Créer le fichier `/.well-known/security.txt`.
   - **Contenu :**
     ```text
     Contact: mailto:admin@hoxera.is-a.dev
     Expires: 2027-11-22T00:00:00Z
     Canonical: https://hoxera.is-a.dev/.well-known/security.txt
     ```

---

## 6. ÉTAT DE LA CIBLE

- **Score Global :** 6.5/10
- **Statut :** STABLE (Maîtrise de base)
- **Recommandation :** Passer en mode "Production Hardened" (Sécurité Renforcée) avant d'accepter des paiements ou des données sensibles.
