# Rapport de durcissement d’un serveur web sous Rocky Linux 9

## 1. Objectif

Le but est de durcir la configuration d'un système, d'un serveur web, d'une base de données, et d'un CMS, à partir des recommandations des benchmarks CIS et des guides de sécurité des éditeurs.

---

## 2. Stack technique

| Composant        | Choix technique          |
|------------------|--------------------------|
| OS               | Rocky Linux 9            |
| Serveur Web      | Apache HTTP Server 2.4   |
| Base de données  | MariaDB 10.6             |
| CMS              | WordPress                |
| Firewall         | firewalld                |
| WAF              | ModSecurity + OWASP CRS  |

---

## 3. Sources utilisées

- CIS Benchmark RHEL 9 (compatible Rocky Linux)  
  [https://www.cisecurity.org/benchmark/red_hat_linux](https://www.cisecurity.org/benchmark/red_hat_linux)
- CIS Benchmark Apache HTTP Server 2.4
  [https://www.cisecurity.org/benchmark/apache_http_server](https://www.cisecurity.org/benchmark/apache_http_server)
- CIS Benchmark MariaDB 10.6  
  [https://www.cisecurity.org/benchmark/mariadb](https://www.cisecurity.org/benchmark/mariadb)
- Sécurité WordPress (guide officiel)  
  [https://developer.wordpress.org/advanced-administration/security/hardening/](https://developer.wordpress.org/advanced-administration/security/hardening/)

---

## 4. Mesures de durcissement

### 4.1 Système d’exploitation (Rocky Linux 9)

| Mesure | Détail | Justification |
|--------|--------|---------------|
| Activer `firewalld` | Autoriser uniquement HTTP, HTTPS, SSH | Contrôle des ports ouverts |
| SSH par clés uniquement | `PasswordAuthentication no` ; `PubkeyAuthentication yes` | Évite attaques par dictionnaire |
| Désactiver SSH root | `PermitRootLogin no` | Supprime le compte cible classique |
| Limiter le nombre de tentatives SSH | via `fail2ban` | Mitige brute force |
| Activer `auditd` | Journaliser les événements système | Suivi des activités critiques |
| Supprimer paquets inutiles | `dnf remove` des services inutiles | Réduire la surface d’attaque |
| Activer SELinux (en mode enforcing) | Renforcement du contrôle d’accès | Politique de sécurité forte |
| Activer les mises à jour automatiques | via `dnf-automatic` | Limite les vulnérabilités non patchées |
| Isoler `/var/www` dans un LV séparé | Monté avec `nodev,noexec,nosuid` | Empêche l'exécution directe de fichiers malveillants uploadés dans l’espace web |
| Isoler `/tmp` dans un LV séparé | Monté avec `nodev,noexec,nosuid` | Empêchel' exécution de scripts dans l’espace temporaire commun |
| Vérifier les permissions sur les fichiers système |/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/sudoers, /etc/ssh/sshd_config | Éviter les fuites ou modifications |
| Restreindre `cron` | autoriser uniquement root ou whitelist | Empêche scripts non autorisés |

---

### 4.2 Apache HTTP Server

| Mesure | Détail | Justification |
|--------|--------|---------------|
| Désactiver la signature serveur | `ServerSignature Off`, `ServerTokens Prod` | Réduit les infos exposées |
| Forcer HTTPS | via Let's Encrypt + redirection 80 → 443 | Communication chiffrée |
| Désactiver directory listing | `Options -Indexes` | Cache l’arborescence |
| Empêcher l’exécution de scripts dans `/uploads` | config `.htaccess` | Protège contre upload malveillant |
| Utiliser ModSecurity + OWASP CRS | WAF côté serveur | Protection XSS, SQLi, LFI, etc. |
| Restreindre l'accès aux fichiers sensibles | `.htaccess` pour `.env`, `.git` | Protège infos config |
| Activer les headers de sécurité | CSP, X-Frame-Options, X-XSS-Protection | Protection navigateur |
| Bloquer les méthodes HTTP inutiles | `LimitExcept GET POST` | Réduit les vecteurs d'attaque |
| Utiliser un compte utilisateur dédié `apache` | Séparation des privilèges | Moins de droits = moins de risques |

---

### 4.3 Base de données : MariaDB

| Mesure | Détail | Justification |
|--------|--------|---------------|
| Supprimer utilisateurs anonymes | `DELETE FROM mysql.user WHERE User=''` | Supprime accès anonyme |
| Supprimer la base `test` | `DROP DATABASE test` | Évite abus de base ouverte |
| Restreindre l’accès root à `localhost` | `bind-address = 127.0.0.1` | Évite accès distant root |
| Créer un utilisateur WordPress avec droits limités | SELECT, INSERT, UPDATE, DELETE | Principe du moindre privilège |
| Auditer les permissions | Pas de `GRANT ALL` | Réduire les privilèges |
| Sauvegarder régulièrement les données | Script cron + `mysqldump` | Protection contre perte ou compromission |
| Journaliser les requêtes lentes | `slow_query_log = 1` | Analyse de comportement suspect |
| Utiliser un mot de passe fort et stocké hors repo | Fichier de config sécurisé | Éviter le hardcoded credentials |

---

### 4.4 WordPress (application)

| Mesure | Détail | Justification |
|--------|--------|---------------|
| Supprimer `readme.html`, `xmlrpc.php` | ou désactiver XML-RPC | Réduit la surface d’attaque |
| Modifier le préfixe des tables (`wp_`) | au moment de l’installation | Évite injections génériques |
| Installer un plugin de sécurité | Wordfence | Fournit une couche de sécurité applicative : détection d’altérations de fichiers WordPress, protection contre les attaques par force brute, pare-feu applicatif, scans réguliers, blocage d’IP suspectes, et alertes en temps réel |
| Forcer HTTPS dans `wp-config.php` et `functions.php` | Redirection et `is_ssl()` | Sécurise toutes les pages |
| Définir les clés de sécurité (`AUTH_KEY`, etc.) | via [https://api.wordpress.org/secret-key](https://api.wordpress.org/secret-key) | Protège les sessions |
| Désactiver l’édition de fichiers via le backoffice | `DISALLOW_FILE_EDIT` | Empêche exploitation via admin |
| Mettre à jour core, plugins, thèmes | Automatiquement via wp-config.php | Corrige les vulnérabilités |
| Éviter les plugins obsolètes/non maintenus | Vérifier sur le repo WP officiel | Réduit le risque d'exploit |
