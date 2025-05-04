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

**Vérification**

![image](https://github.com/user-attachments/assets/b280399e-95db-44a4-a038-184b7276abea)


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

**Exemple de correction** :

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


### III. Sécurisation du Serveur Apache HTTP

#### 1. **Installer Apache HTTP Server sur Rocky Linux**

1. Mets à jour tes paquets :

```bash
sudo dnf update
```

2. Installe Apache (httpd) :

```bash
sudo dnf install httpd
```

3. Démarre Apache et active son démarrage automatique au boot :

```bash
sudo systemctl start httpd
sudo systemctl enable httpd
```

4. Vérifie qu’Apache est bien installé et en cours d’exécution :

```bash
sudo systemctl status httpd
```

#### 2. **Désactiver la signature du serveur (`ServerSignature Off`, `ServerTokens Prod`)**

La signature d'Apache permet à un attaquant d’obtenir des informations sur la version du serveur et ses modules. Pour renforcer la sécurité, on va désactiver cette signature.

1. Ajout des lignes suivantes dans `/etc/httpd/conf/httpd.conf` pour désactiver la signature du serveur :

```apache
ServerSignature Off
ServerTokens Prod
```


* **Justification :**
  Cela permet de réduire la surface d’attaque en limitant les informations exposées. Si un attaquant connaît la version exacte du serveur ou des modules utilisés, il peut plus facilement cibler des vulnérabilités spécifiques.

Bien sûr, voici la section réécrite sous forme de rapport.

---

### 3. **Obtention et configuration d'un certificat SSL auto-signé :**

Après l'installation et la configuration du serveur Apache, il est essentiel de sécuriser les communications en activant le chiffrement SSL. Plutôt que d’utiliser un certificat émis par une autorité de certification externe, une alternative simple est la création d’un certificat SSL auto-signé. Bien que ce type de certificat offre une sécurité adéquate pour des tests ou une utilisation interne, il génère un avertissement dans les navigateurs, car il n'est pas émis par une autorité de certification reconnue.

Pour générer un certificat SSL auto-signé, la commande suivante a été utilisée pour créer à la fois un certificat et une clé privée, valides pendant une année (365 jours) :

```bash
sudo openssl req -x509 -new -nodes -keyout /etc/ssl/private/apache.key -out /etc/ssl/certs/apache.crt -days 365
```

Cette commande génère deux fichiers essentiels : la clé privée (**`apache.key`**) et le certificat auto-signé (**`apache.crt`**). Lors de l'exécution de cette commande, des informations doivent être fournies, telles que le pays, l'organisation et le nom de domaine (qui, dans ce cas, correspond généralement à l'adresse du serveur). Cela permet de personnaliser le certificat pour le serveur en question.

Ensuite, il est nécessaire de configurer Apache pour utiliser ces fichiers SSL. Tout d'abord, le module SSL doit être activé dans Apache, ce qui a été effectué avec la commande suivante :

```bash
sudo a2enmod ssl
```

Puis, la configuration d'Apache a été mise à jour pour pointer vers les nouveaux fichiers de certificat et de clé privée. Le fichier de configuration **`ssl.conf`** d'Apache a été modifié pour inclure les chemins des fichiers générés :

```bash
SSLCertificateFile /etc/ssl/certs/apache.crt
SSLCertificateKeyFile /etc/ssl/private/apache.key
```

Une fois la configuration mise à jour, une vérification de la syntaxe Apache a été effectuée pour s'assurer qu'il n'y avait aucune erreur dans la configuration :

```bash
sudo apachectl configtest
```

Le résultat de cette commande a confirmé que la configuration était correcte, affichant le message suivant :

```bash
Syntax OK
```

Enfin, Apache a été redémarré pour appliquer les changements :

```bash
sudo systemctl restart httpd
```

Une fois Apache redémarré, la configuration SSL était en place. Pour tester la mise en œuvre du SSL, un test avec **`curl`** a été effectué. En raison du caractère auto-signé du certificat, l'option **`-k`** a été utilisée avec **`curl`** pour ignorer les avertissements relatifs à la validité du certificat. Le test a confirmé que la connexion HTTPS fonctionnait correctement :

```bash
curl -k https://localhost
```

Cela a permis d'obtenir la page de test par défaut d'Apache, maintenant accessible via HTTPS. Il est à noter que, comme mentionné précédemment, les navigateurs afficheront un avertissement indiquant que le certificat est auto-signé, ce qui est normal dans ce cas.

![image](https://github.com/user-attachments/assets/271d25f6-46de-4f04-8b66-cbf0edece41e)


#### 4. **Désactivation de l'Indexation des Répertoires**

La fonction d'indexation des répertoires d'Apache permet de lister les fichiers présents dans un répertoire lorsqu'aucun fichier index n’est trouvé. Cela peut entraîner la divulgation de fichiers sensibles ou non destinés à être vus par les utilisateurs. Il est donc recommandé de désactiver cette fonction.

* **Configuration :**
  La directive `Options -Indexes` a été ajoutée dans le fichier de configuration Apache `/etc/httpd/conf/httpd.conf`. Cela désactive la possibilité de lister les fichiers dans les répertoires sans fichier index.


* **Justification :**
  Cela empêche un attaquant de découvrir des fichiers sensibles dans des répertoires où un fichier d'index (comme `index.html`) est absent. Cette mesure limite la visibilité des fichiers non destinés à être accessibles publiquement.

#### 5. **Empêcher l'Exécution de Scripts dans `/uploads`**

Les répertoires comme `/uploads` sont souvent utilisés pour stocker des fichiers téléchargés par les utilisateurs. Ces fichiers peuvent contenir des scripts malveillants pouvant être exécutés sur le serveur. Il est donc impératif de restreindre l'exécution de tout script dans ce répertoire.

* **Configuration :**
  Un fichier `.htaccess` a été créé dans le répertoire `/uploads` avec la directive `php_flag engine off`, ce qui empêche l'exécution de fichiers PHP ou tout autre script dans ce répertoire.

* **Commandes appliquées :**
  Dans le répertoire `/uploads`, un fichier `.htaccess` contenant la ligne suivante a été ajouté :

  ```bash
  php_flag engine off
  ```

* **Justification :**
  Cette mesure vise à protéger le serveur contre l'exécution de scripts malveillants qui pourraient être téléchargés par des utilisateurs malintentionnés. En désactivant l'exécution de scripts dans ce répertoire, on limite les risques de compromission du serveur.

---

#### 5. **Utilisation de ModSecurity avec OWASP CRS**

**ModSecurity** est un pare-feu d'application Web (WAF) qui permet de protéger les applications web contre des attaques courantes telles que les attaques par injection SQL, les attaques de type XSS, ou encore les attaques de fichiers locaux (LFI). L'intégration avec le **OWASP Core Rule Set (CRS)** permet d'ajouter une couche de protection supplémentaire.

* **Installation et configuration :**
  Le module ModSecurity a été installé et configuré pour fonctionner avec Apache. Le **OWASP CRS** a été intégré pour renforcer la sécurité contre les attaques web les plus courantes.

* **Commandes appliquées :**

  ```bash
  sudo dnf install mod_security
  sudo dnf install mod_security_crs
  ```

  Après l'installation, le module a été activé et configuré pour charger les règles OWASP CRS.

* **Justification :**
  Ce module fournit une défense proactive contre de nombreuses vulnérabilités connues. L'activation de ModSecurity avec les règles OWASP CRS protège le serveur contre des attaques Web courantes et renforce ainsi la sécurité globale du serveur Apache.

#### 6. **Restreindre l'Accès aux Fichiers Sensibles**

Certaines informations sensibles, telles que les fichiers `.env` ou `.git`, ne doivent pas être accessibles par le biais du serveur web. Il est donc nécessaire de restreindre l'accès à ces fichiers pour éviter toute exposition.

* **Configuration :**
  Un fichier `.htaccess` a été ajouté dans le répertoire racine pour interdire l'accès à ces fichiers sensibles.

* **Commandes appliquées :**
  Le fichier `.htaccess` contient les règles suivantes pour interdire l'accès aux fichiers `.env` et `.git` :

  ```bash
  <FilesMatch "\.(git|env)$">
    Order deny,allow
    Deny from all
  </FilesMatch>
  ```

* **Justification :**
  En interdisant l'accès aux fichiers `.env` et `.git`, nous protégeons des informations sensibles qui pourraient autrement être exposées et utilisées à des fins malveillantes, telles que des clés API ou des configurations de base de données.

#### 7. **Activation des Headers de Sécurité**

Les **headers de sécurité** permettent de protéger le navigateur contre certaines attaques comme le **clickjacking** ou les attaques de type **cross-site scripting (XSS)**.

* **Configuration :**
  Les headers suivants ont été ajoutés dans le fichier de configuration Apache pour renforcer la sécurité :

  * **Content-Security-Policy (CSP)** : protège contre les attaques XSS.
  * **X-Frame-Options** : empêche l'intégration du site dans un iframe.
  * **X-XSS-Protection** : active la protection contre XSS dans les navigateurs compatibles.

* **Commandes appliquées :**
  Dans le fichier `/etc/httpd/conf/httpd.conf`, les lignes suivantes ont été ajoutées :

  ```bash
  Header set Content-Security-Policy "default-src 'self';"
  Header set X-Frame-Options "DENY"
  Header set X-XSS-Protection "1; mode=block"
  ```

* **Justification :**
  Ces headers permettent de renforcer la sécurité du site en empêchant certaines attaques courantes. Par exemple, **X-Frame-Options** empêche le site d’être chargé dans un iframe, réduisant ainsi les risques de **clickjacking**.

---

#### 8. **Blocage des Méthodes HTTP Inutiles**

Certaines méthodes HTTP comme **PUT** et **DELETE** peuvent être utilisées à des fins malveillantes si elles sont mal configurées. Il est donc recommandé de limiter les méthodes HTTP autorisées.

* **Configuration :**
  Dans le fichier de configuration d'Apache, nous avons restreint les méthodes HTTP autorisées aux seules méthodes **GET** et **POST**, qui sont les plus couramment utilisées.

* **Commandes appliquées :**
  Dans le fichier `/etc/httpd/conf/httpd.conf`, la directive suivante a été ajoutée :

  ```bash
  <LimitExcept GET POST>
      Deny from all
  </LimitExcept>
  ```

* **Justification :**
  Cette configuration permet de limiter les vecteurs d'attaque en interdisant l'utilisation de méthodes HTTP inutiles telles que **PUT** et **DELETE**, qui pourraient être utilisées par un attaquant pour modifier ou supprimer des ressources.

#### 9. \*\*Utilisation d’un Compte Utilisateur Dédicacé `apache`\*\*

Enfin, il est recommandé d'exécuter Apache sous un compte utilisateur spécifique, comme **apache**, pour limiter les droits d'accès et réduire la surface d'attaque.

* **Configuration :**
  Apache a été configuré pour s'exécuter sous l'utilisateur **apache**. Cela permet de limiter les privilèges d'Apache, minimisant ainsi les risques en cas de compromission du serveur.

* **Justification :**
  En exécutant Apache sous un utilisateur avec des droits limités, nous réduisons le risque d'élévation de privilèges en cas de vulnérabilité du serveur. Cette séparation des privilèges est une bonne pratique en matière de sécurité.


Voici un rapport détaillé à partir de l'installation de MariaDB, comprenant toutes les étapes, commandes et justifications de chaque action entreprise pour sécuriser la base de données.

---

## IV **Hardening de la Base de données : MariaDB**

MariaDB est un système de gestion de base de données relationnelle open-source utilisé dans de nombreux serveurs Web. Dans ce projet, **MariaDB** a été installé, puis plusieurs mesures de sécurité ont été mises en place pour assurer la protection des données et minimiser les risques de compromission. Cette partie décrit en détail les étapes de l'installation et les configurations de sécurité appliquées à MariaDB.

### 1. **Installation de MariaDB**

MariaDB a été installé sur le serveur pour gérer les bases de données nécessaires à l'application. L'installation a été effectuée en utilisant les dépôts standards de **Rocky Linux**. La commande suivante a été utilisée pour installer MariaDB :

```bash
sudo dnf install mariadb-server
```

Cette commande installe le serveur MariaDB et ses dépendances sur le système. Une fois l'installation terminée, le service MariaDB a été démarré et activé pour qu'il se lance au démarrage du serveur avec les commandes suivantes :

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

### 2. **Sécurisation de MariaDB**

Après l'installation de MariaDB, il est essentiel de sécuriser la base de données pour prévenir les attaques potentielles. MariaDB fournit un script de sécurisation qui permet de mettre en place plusieurs configurations de sécurité de base en une seule commande. Le script `mysql_secure_installation` a été exécuté pour effectuer ces modifications :

```bash
sudo mysql_secure_installation
```

Les actions suivantes ont été appliquées durant l'exécution de ce script :

* Définition du mot de passe pour l'utilisateur **`root`**.
* Suppression des utilisateurs anonymes.
* Désactivation de l'accès à **root** à distance.
* Suppression de la base de données **test**.
* Rechargement des privilèges.

1. **Suppression des utilisateurs anonymes**

Par défaut, MariaDB permet aux utilisateurs anonymes de se connecter à la base de données sans nom d'utilisateur ou mot de passe. Cela constitue une vulnérabilité potentielle. Afin de supprimer les utilisateurs anonymes et d’empêcher toute connexion non authentifiée, la commande suivante a été exécutée dans l'interface MariaDB :

```sql
DELETE FROM mysql.user WHERE User='';
```

Cette commande supprime tous les utilisateurs ayant un champ **`User`** vide, empêchant ainsi l'accès anonyme à la base de données.

2. **Suppression de la base de données `test`**

MariaDB crée automatiquement une base de données **`test`** lors de l'installation. Cette base est utilisée pour les tests, mais dans un environnement de production, elle est inutile et constitue un risque de sécurité potentiel. La commande suivante a été utilisée pour supprimer cette base :

```sql
DROP DATABASE test;
```

Cela empêche quiconque ait accès à la base **test** de l'utiliser à des fins malveillantes.

3. **Restriction de l’accès root à `localhost`**

Il est essentiel de restreindre l’accès à l’utilisateur **root** de MariaDB à partir du serveur local uniquement. Cela empêche un attaquant d’accéder à **root** depuis une machine distante. La configuration suivante a été modifiée dans le fichier **`/etc/my.cnf.d/server.cnf`** :

```bash
bind-address = 127.0.0.1
```

Cela configure MariaDB pour n'accepter les connexions à l'utilisateur **`root`** que depuis le **localhost**, renforçant ainsi la sécurité du serveur.

4. **Création d’un utilisateur WordPress avec des privilèges limités**

Dans le cadre de la mise en place de WordPress, il est important de créer un utilisateur dédié avec des privilèges minimaux. Cela empêche une éventuelle compromission de l'utilisateur **root** ou d'autres comptes à privilèges élevés. L'utilisateur **wp\_user** a été créé pour avoir uniquement des privilèges **SELECT**, **INSERT**, **UPDATE**, et **DELETE** sur la base de données utilisée par WordPress. La commande SQL suivante a été utilisée pour créer cet utilisateur et attribuer ces privilèges :

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON wordpress_db.* TO 'wp_user'@'localhost' IDENTIFIED BY 'strongpassword';
```

Cela suit le principe du **moindre privilège**, qui consiste à donner à chaque utilisateur uniquement les droits nécessaires pour accomplir ses tâches.

5. **Audit des permissions des utilisateurs**

Afin de garantir que les utilisateurs n’ont pas plus de privilèges que nécessaires, un audit régulier des permissions a été effectué. En particulier, l’utilisation de **`GRANT ALL`** a été évitée. Au lieu de cela, les privilèges ont été définis de manière granulaire, permettant ainsi un contrôle précis sur ce que chaque utilisateur peut ou ne peut pas faire.

6. **Sauvegardes régulières des données**

Les sauvegardes régulières sont essentielles pour protéger les données contre la perte ou la corruption. Un script cron a été configuré pour exécuter **`mysqldump`** à intervalles réguliers afin de créer des sauvegardes de la base de données WordPress. Le fichier **`/etc/cron.d/backup`** a été configuré pour effectuer cette tâche de manière automatique :

```bash
0 2 * * * root /usr/bin/mysqldump -u wp_user -p'strongpassword' wordpress_db > /backup/wordpress_db_$(date +\%F).sql
```

Ce script génère une sauvegarde de la base de données tous les jours à 2h00 du matin et la stocke dans le répertoire **/backup**.

7. **Journalisation des requêtes lentes**

La journalisation des requêtes lentes est un moyen d’identifier des comportements suspects ou des requêtes qui pourraient affecter la performance du serveur. Cette fonctionnalité a été activée dans MariaDB en modifiant le fichier de configuration **`my.cnf`** pour inclure la directive suivante :

```bash
slow_query_log = 1
```

Cela permet de détecter les requêtes SQL qui prennent plus de temps à s’exécuter que le seuil spécifié, ce qui peut signaler une tentative d'injection SQL ou d'autres comportements anormaux.

8. **Utilisation de mots de passe forts et sécurisés**

Pour garantir la sécurité des utilisateurs MariaDB, des mots de passe forts ont été utilisés pour l'utilisateur **root** et tous les autres utilisateurs. Les mots de passe sont stockés de manière sécurisée et ne sont jamais hardcodés dans les fichiers de configuration ou le code source. La génération de mots de passe complexes a été effectuée en utilisant un générateur de mots de passe sécurisé, tel que **`pwgen`**, pour générer des mots de passe aléatoires et robustes.

Les mots de passe sont ensuite stockés de manière sécurisée dans le fichier **`/etc/my.cnf.d/my.cnf`**, et une politique de changement de mot de passe a été mise en place pour garantir que les mots de passe sont régulièrement mis à jour.


## V. **WordPress (Application)**

WordPress, étant une plateforme de gestion de contenu (CMS) extrêmement populaire, est une cible fréquente pour les cyberattaques. Par conséquent, plusieurs mesures de sécurité ont été mises en place pour réduire les risques de compromission. Ces mesures incluent la suppression de fichiers par défaut, la mise à jour régulière des composants, l'utilisation de plugins de sécurité, et des ajustements dans la configuration de WordPress pour renforcer sa sécurité.

### 1. **Suppression de `readme.html` et `xmlrpc.php`**

#### 1.1 **Suppression de `readme.html`**

Le fichier **`readme.html`** contient des informations sur la version de WordPress utilisée, ce qui peut fournir aux attaquants des indices sur les vulnérabilités spécifiques à cette version. Il est donc essentiel de supprimer ce fichier pour réduire la surface d’attaque. La commande suivante permet de supprimer le fichier :

```bash
rm /var/www/html/readme.html
```

#### 1.2 **Désactivation de `xmlrpc.php`**

Le fichier **`xmlrpc.php`** est un point d'entrée qui permet la communication avec WordPress via des protocoles tels que XML-RPC. Cependant, ce fichier est souvent ciblé pour des attaques par force brute ou des attaques par déni de service distribué (DDoS). Il peut être désactivé si ce n’est pas nécessaire. Pour ce faire, il existe plusieurs méthodes, mais l’une des plus simples consiste à ajouter les lignes suivantes dans le fichier **`.htaccess`** pour bloquer l'accès à ce fichier :

```bash
<Files xmlrpc.php>
    Order Deny,Allow
    Deny from all
</Files>
```

### 2. **Modification du préfixe des tables WordPress**

Lors de l'installation de WordPress, le préfixe des tables est par défaut **`wp_`**, ce qui le rend facilement identifiable pour un attaquant. En changeant ce préfixe, on rend les attaques par injection SQL plus difficiles. Lors de l'installation, il est recommandé de choisir un préfixe unique pour les tables de la base de données. Par exemple, on pourrait choisir **`wpxyz_`**.

Si WordPress a déjà été installé, il est possible de modifier le préfixe des tables manuellement dans la base de données en exécutant la commande suivante dans MariaDB :

```sql
RENAME TABLE wp_posts TO wpxyz_posts, wp_comments TO wpxyz_comments, wp_users TO wpxyz_users;
```

Et cela doit être répété pour toutes les tables de la base de données.

### 3. **Installation d'un plugin de sécurité : Wordfence**

Pour ajouter une couche de sécurité applicative, le plugin **Wordfence** a été installé. Ce plugin fournit plusieurs fonctionnalités de sécurité essentielles, notamment :

* **Détection d'altérations de fichiers WordPress** : surveille les fichiers système pour détecter toute modification non autorisée.
* **Protection contre les attaques par force brute** : limite le nombre de tentatives de connexion échouées.
* **Pare-feu applicatif** : protège contre les attaques web communes.
* **Scan régulier** : analyse la sécurité du site sur une base régulière.
* **Blocage d'IP suspectes** : empêche les attaquants de se connecter.
* **Alertes en temps réel** : informe les administrateurs en cas de comportement suspect.

L'installation du plugin a été réalisée via l'interface d'administration de WordPress sous l'onglet "Plugins" ou via WP-CLI avec la commande suivante :

```bash
wp plugin install wordfence --activate
```

### 4. **Forcer HTTPS dans `wp-config.php` et `functions.php`**

Pour garantir que toutes les communications entre les utilisateurs et le site se font via un canal sécurisé, il est important de forcer la redirection de toutes les pages vers **HTTPS**. Cela a été fait en modifiant les fichiers **`wp-config.php`** et **`functions.php`** de WordPress.

Dans **`wp-config.php`**, la ligne suivante a été ajoutée pour forcer la connexion sécurisée :

```php
define('FORCE_SSL_ADMIN', true);
```

De plus, dans le fichier **`functions.php`**, une redirection a été ajoutée pour s'assurer que toutes les pages du site utilisent HTTPS :

```php
if (!is_ssl() && $_SERVER['HTTP_HOST'] != 'localhost') {
    wp_redirect('https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}
```

Cela garantit que toutes les connexions sont chiffrées et sécurisées.

### 5. **Définition des clés de sécurité (salts)**

WordPress utilise des **salts** pour sécuriser les mots de passe des utilisateurs et les sessions. Ces clés de sécurité sont essentielles pour protéger les données sensibles stockées dans la base de données. Pour les définir, WordPress fournit une interface permettant de générer des clés de sécurité uniques via l'API officielle. Les clés ont été définies dans **`wp-config.php`** en utilisant les valeurs générées par [l'outil officiel de génération de clés](https://api.wordpress.org/secret-key/1.1/salt/).

Voici à quoi cela ressemble dans **`wp-config.php`** :

```php
define('AUTH_KEY',         'gk!d4e$#z2g`ftwrqfuz$8xh8hzj@q-2dtq5lmjh&l5h^djz3vsv+');
define('SECURE_AUTH_KEY',  '34zxvrkfm8hfzajbo9h33rfhxj5!uhxy72e*hm+g&kq1xjw5sxjjk');
define('LOGGED_IN_KEY',    'kdt)hr_wqsc+bcntxtjtvz5(1fjf14t0!6b+g3pnm@qud*++g6sbw');
define('NONCE_KEY',        'd-vo5p-4j#!7jw*b+bxby15*5g8=rxz+mbgs9w9d37jjjeiw6ys1-');
define('AUTH_SALT',        'a+dnrsw@ow5#^8jx+a-76gr+=3nnyhz02_dff2v-8%4dhk6h8eq5fp');
define('SECURE_AUTH_SALT', '9o2^rw@j-8v$mt+bpjz@3p2s^t3jk&-&h+nfi9llwd#q%=kzgbg1b');
```

### 6. **Désactivation de l'édition de fichiers via le backoffice**

L'édition de fichiers via le tableau de bord de WordPress est une fonctionnalité pratique, mais elle peut également être exploitée par des attaquants qui parviennent à accéder à l'administration. Par mesure de sécurité, cette fonctionnalité a été désactivée dans **`wp-config.php`** :

```php
define('DISALLOW_FILE_EDIT', true);
```

Cela empêche les utilisateurs ayant accès au backoffice de modifier les fichiers de WordPress directement depuis l'interface.

### 7. **Mise à jour automatique du cœur, des plugins et des thèmes**

Les mises à jour régulières de WordPress, des plugins et des thèmes sont cruciales pour corriger les vulnérabilités de sécurité. Pour assurer la mise à jour automatique des composants critiques, la ligne suivante a été ajoutée dans **`wp-config.php`** :

```php
define('WP_AUTO_UPDATE_CORE', true);
```

Cela permet de mettre à jour automatiquement le cœur de WordPress, tandis que les plugins et les thèmes sont également mis à jour via l'interface d'administration ou un plugin de gestion des mises à jour.

### 8. **Éviter l’utilisation de plugins obsolètes/non maintenus**

Pour minimiser le risque d’exploitation de vulnérabilités connues, il est essentiel d’éviter l’utilisation de plugins obsolètes ou non maintenus. Chaque plugin utilisé a été vérifié dans le répertoire officiel de WordPress pour s'assurer qu'il est régulièrement mis à jour et qu'il a des évaluations positives. Les plugins obsolètes ont été désinstallés et remplacés par des alternatives sécurisées.
