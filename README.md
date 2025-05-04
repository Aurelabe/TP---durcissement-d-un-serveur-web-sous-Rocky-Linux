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
| Définir les clés de sécurité `AUTH_KEY`, etc.) | salts via [https://api.wordpress.org/secret-key](https://api.wordpress.org/secret-key/1.1/salt/) | Protège les sessions |
| Désactiver l’édition de fichiers via le backoffice | `DISALLOW_FILE_EDIT` | Empêche exploitation via admin |
| Mettre à jour core, plugins, thèmes | Automatiquement via wp-config.php | Corrige les vulnérabilités |
| Éviter les plugins obsolètes/non maintenus | Vérifier sur le repo WP officiel | Réduit le risque d'exploit |


# II. Durcissement du système d’exploitation (Rocky Linux 9)

## 1. Configuration réseau avec `nmcli`

**Objectif** : Définir une adresse IP statique pour assurer une connectivité réseau stable et prévisible, essentielle pour un serveur.

**Actions réalisées** :

* **Modification de la configuration de l'interface** :
  Supposons que l'interface concernée soit `enp0s8` :

  ```bash
  nmcli con mod enp0s8 ipv4.addresses 10.1.1.17/24
  nmcli con mod enp0s8 ipv4.gateway 10.1.1.1
  nmcli con mod enp0s8 ipv4.dns "8.8.8.8 8.8.4.4"
  nmcli con mod enp0s8 ipv4.method manual
  ```

  Ces commandes définissent une adresse IP statique, une passerelle et des serveurs DNS pour l'interface.

* **Redémarrage de la connexion pour appliquer les modifications** :

  ```bash
  nmcli con down enp0s8 && nmcli con up enp0s8
  ```

**Justification** : L'utilisation d'une adresse IP statique garantit que le serveur est toujours accessible à la même adresse, ce qui est crucial pour les services tels que les serveurs web ou les bases de données.

## 2. Configuration de `firewalld`

**Objectif** : Restreindre l'accès au serveur en n'autorisant que les ports nécessaires, réduisant ainsi la surface d'attaque.

**Actions réalisées** :

* **Création de la zone `restricted`** :

  ```bash
  sudo firewall-cmd --permanent --new-zone=restricted
  ```

  Cela crée une nouvelle zone avec des règles de sécurité personnalisées.

* **Ajout des interfaces réseau à la zone `restricted`** :

  ```bash
  sudo firewall-cmd --permanent --zone=restricted --add-interface=enp0s3
  sudo firewall-cmd --permanent --zone=restricted --add-interface=enp0s8
  ```

  ![Capture d'écran 2025-04-25 164318](https://github.com/user-attachments/assets/769379f9-eba7-4e02-9799-7aafc524ca67)


  Ces commandes ajoutent les interfaces réseau `enp0s3` et `enp0s8` à la zone `restricted`.

* **Suppression de tous les services de la zone `public`** :

  ![Capture d'écran 2025-04-25 163735](https://github.com/user-attachments/assets/4827cca4-ded4-4dd6-85b9-93d8bc699d6a)
  
  Cela retire les services précédemment autorisés dans la zone `public`.

* **Ouverture des ports nécessaires dans la zone `restricted`** :

  ```bash
  sudo firewall-cmd --permanent --zone=restricted --add-port=80/tcp
  sudo firewall-cmd --permanent --zone=restricted --add-port=443/tcp
  sudo firewall-cmd --permanent --zone=restricted --add-port=1025/tcp
  ```

  Cela autorise uniquement les ports 80 (HTTP), 443 (HTTPS) et 1025 (SSH personnalisé) dans la zone `restricted`.

* **Application des modifications** :

  ```bash
  sudo firewall-cmd --reload
  ```

* **Vérification de la configuration actuelle** :

  ```bash
  sudo firewall-cmd --list-all
  ```

  ![Capture d'écran 2025-04-25 164007](https://github.com/user-attachments/assets/307118aa-0557-4075-87f3-6d234d4465d8)


**Justification** : En supprimant tous les services non essentiels et en n'autorisant que les ports nécessaires dans une zone dédiée, on réduit considérablement les vecteurs d'attaque potentiels.

## 3. Configuration de SSH et installation de `fail2ban`

**Objectif** : Sécuriser l'accès SSH et prévenir les tentatives d'accès non autorisées.

**Actions réalisées** :

* **Modification de la configuration SSH** :

  ```bash
  sudo nano /etc/ssh/sshd_config
  ```

  Dans le fichier de configuration, les lignes suivantes ont été modifiées ou ajoutées :

  ```bash
  Port 1025
  Protocol 2
  PermitRootLogin no
  PasswordAuthentication no
  PubkeyAuthentication yes
  PermitEmptyPasswords no
  AllowUsers admin
  ```

  Ces paramètres désactivent l'accès root direct, l'authentification par mot de passe, et forcent l'utilisation de clés SSH.

* **Redémarrage du service SSH pour appliquer les modifications** :

  ```bash
  sudo systemctl restart sshd
  ```

* **Installation de `fail2ban`** :

  ```bash
  sudo dnf install fail2ban
  ```

* **Activation et démarrage de `fail2ban`** :

  ```bash
  sudo systemctl enable --now fail2ban
  sudo systemctl start --now fail2ban
  ```

* **Création d'une configuration personnalisée pour SSH** :

  ```bash
  sudo nano /etc/fail2ban/jail.d/sshd.local
  ```

  Contenu du fichier :

  ```ini
  [sshd]
  enabled = true
  port = 1025
  filter = sshd
  logpath = /var/log/secure
  maxretry = 3
  bantime = 1d
  backend = systemd
  ```

  Cette configuration définit les paramètres spécifiques pour le service SSH, tels que le port personnalisé, le chemin du journal, le nombre maximal de tentatives avant bannissement, la durée du bannissement et le backend utilisé.

* **Vérification du statut de `fail2ban`** :

  ```bash
  sudo systemctl status fail2ban
  ```

**Justification** : La désactivation de l'accès root et de l'authentification par mot de passe renforce la sécurité SSH. L'installation de `fail2ban` permet de bloquer les adresses IP effectuant des tentatives de connexion répétées, réduisant ainsi le risque d'attaques par force brute.


Parfait. Poursuivons maintenant avec la mise en œuvre des autres mesures de durcissement du système d’exploitation listées dans ton rappel. Je vais t’expliquer chaque action étape par étape pour que tu puisses à la fois l’appliquer et la documenter ensuite dans ton rapport GitHub.

### 4. Activation de `auditd`

**Objectif** : Mettre en place un système d’audit pour tracer toutes les actions sensibles sur le système.

**Actions** :

```bash
sudo dnf install audit
sudo systemctl enable --now auditd
```

**Vérification** :

```bash
sudo auditctl -s
```

![Capture d'écran 2025-05-04 180837](https://github.com/user-attachments/assets/210ceeaf-5196-4138-8a05-bb2690f665ca)


**Justification** : Permet la traçabilité des actions utilisateurs, modifications de fichiers critiques, escalades de privilèges, etc.

### 5. Suppression des paquets inutiles

**Objectif** : Réduire la surface d’attaque en supprimant les logiciels non nécessaires.

**Procédure** :

**Supprimer les paquets inutiles** :

   ```bash
   sudo dnf autoremove
   ```

   Cette commande supprime les paquets installés automatiquement qui ne sont plus requis par d'autres paquets. Il est recommandé de vérifier la liste des paquets proposés à la suppression avant de confirmer, car `dnf autoremove` peut parfois proposer de supprimer des paquets que vous souhaitez conserver.

**Justification** : La suppression des paquets non requis libère des ressources et réduit les vecteurs d’attaque potentiels, surtout si des services inutiles sont exposés et/ou mal configurés.

### 6. Activer SELinux en mode `enforcing`

**Objectif** : Appliquer un contrôle d’accès obligatoire (MAC) plus strict que les permissions UNIX classiques.

**Vérification actuelle** :

```bash
getenforce
```

![Capture d'écran 2025-05-04 182641](https://github.com/user-attachments/assets/5fcc91fa-7db4-4004-9e8a-f557347a673c)


SELinux est déjà en mode `Enforcing`

**Justification** : SELinux limite les actions que les processus peuvent effectuer, même en cas de compromission.

### 7. Activer les mises à jour automatiques

**Objectif** : Garder le système à jour pour limiter les vulnérabilités non corrigées.

**Installation et configuration** :

```bash
sudo dnf install dnf-automatic
sudo systemctl enable --now dnf-automatic.timer
```

**Justification** : Réduit les fenêtres de vulnérabilité entre la publication d’un patch et son application.

### 8. Isolement de `/var/www` dans un volume logique séparé

**Objectif** : Séparer l’espace web du reste du système pour réduire les risques de compromission en cas d’upload de fichiers malveillants.

**Procédure** :

* Un volume logique nommé `var_www` a été créé dans le groupe de volumes `rl_vbox` lors de l'installation du système.

* Le système de fichiers a été formaté en `ext4` :

  ```bash
  sudo mkfs.ext4 /dev/rl_vbox/var_www
  ```

* Le point de montage `/var/www` a été préparé puis monté avec des options restrictives :

  ```bash
  sudo mkdir -p /var/www
  sudo mount -o nodev,noexec,nosuid /dev/rl_vbox/var_www /var/www
  ```

* L’entrée suivante a été ajoutée à `/etc/fstab` pour assurer la persistance au démarrage :

  ```bash
  /dev/rl_vbox/var_www /var/www ext4 defaults,nodev,noexec,nosuid 0 2
  ```

**Vérification**

![Capture d'écran 2025-05-04 212443](https://github.com/user-attachments/assets/52b57c18-2a20-487b-b111-ccf5de99f335)


**Justification** :

L’isolement de `/var/www` empêche :

* l’exécution directe de fichiers binaires (`noexec`)
* l’utilisation de fichiers comme périphériques (`nodev`)
* l'escalade de privilèges via des fichiers avec bit `setuid` ou `setgid` (`nosuid`)

Cela protège le serveur web contre les attaques par upload de fichiers exécutables.

### 9. Isolement de `/tmp` dans un volume logique séparé

**Objectif** : Sécuriser l’espace temporaire accessible à tous les utilisateurs, souvent ciblé par les attaquants pour y exécuter des scripts malveillants.

**Procédure** :

* Un volume logique `tmp` a été alloué dans `rl_vbox` au moment de l’installation.

* Il a été formaté en `xfs`, puis monté temporairement :

  ```bash
  sudo mkfs.xfs /dev/rl_vbox/tmp
  sudo mkdir -p /mnt/tmp
  sudo mount -o nodev,noexec,nosuid /dev/rl_vbox/tmp /mnt/tmp
  ```

* L'ancien `/tmp` a été déplacé, puis le nouveau volume monté en position définitive :

  ```bash
  sudo mv /tmp /tmp.bak
  sudo mkdir /tmp
  sudo mount --move /mnt/tmp /tmp
  sudo chmod 1777 /tmp
  ```

* Ajout à `/etc/fstab` :

  ```bash
  /dev/rl_vbox/tmp /tmp xfs defaults,nodev,noexec,nosuid 0 2
  ```

**Justification** :

* `/tmp` étant accessible par tous les utilisateurs, il est essentiel de restreindre toute exécution de fichiers.
* Les options de montage permettent de limiter les possibilités d’attaques via des scripts ou binaires malicieux.

### 10. Vérification des permissions critiques

**Objectif** : Empêcher les fuites ou modifications non autorisées sur des fichiers système sensibles.

**Commandes** :

```bash
stat /etc/passwd
stat /etc/shadow
stat /etc/group
stat /etc/gshadow
stat /etc/sudoers
stat /etc/ssh/sshd_config
```

Vérifie que :

* `/etc/shadow`, `/etc/gshadow` → `600` (lecture/écriture root uniquement)
* `/etc/passwd`, `/etc/group` → `644`
* `/etc/sudoers` → `440`
* `/etc/ssh/sshd_config` → `600` ou `644`

**Correction exemple** :

```bash
sudo chmod 440 /etc/sudoers
sudo chown root:root /etc/sudoers
```

---

### 11. Restreindre l’accès à `cron`

**Objectif** : Éviter que des utilisateurs non autorisés planifient des tâches automatisées.

**Actions** :

```bash
echo root | sudo tee /etc/cron.allow
sudo touch /etc/cron.deny
```

**Justification** : Limite l’utilisation de `cron` uniquement à des utilisateurs autorisés.

---

Souhaitez-vous que je formalise tout ça dans la suite de votre rapport Markdown maintenant, ou vous voulez d'abord appliquer tout cela sur votre machine ?



