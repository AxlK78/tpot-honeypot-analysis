# Déploiement, Analyse de Télémétrie et Reverse Engineering : Honeypot T-Pot 24.04

Ce projet documente le déploiement en conditions réelles du honeypot multi-services **T-Pot 24.04** sur un serveur dédié virtuel (VPS), son cloisonnement réseau via pare-feu applicatif (`ufw`) et VPN maillé (**Tailscale**), la collecte de plus de **160 000 cyberattaques**, ainsi que la rétro-ingénierie sous **Ghidra** d'une charge utile malveillante interceptée (ver/ransomware WannaCry via DoublePulsar).

---

## 1. Architecture du laboratoire

| Élément | Spécification | Rôle / Description |
| :--- | :--- | :--- |
| **Hébergeur** | Contabo | VPS Cloud haute disponibilité |
| **Système d'exploitation** | Debian 12 (Bookworm) | Noyau Linux 6.1 x86_64 hôte |
| **Plateforme Honeypot** | T-Pot 24.04 CE | Orchestration de conteneurs de leurre multi-protocoles |
| **Sondes analysées** | Cowrie, Dionaea, Sentrypeer | Capture SSH/Telnet, SMB/MSRPC et SIP/VoIP |
| **NIDS & Moteur Log** | Suricata, Elasticsearch, Kibana | Détection réseau et indexation/visualisation en temps réel |
| **Accès Sécurisé** | Tailscale (WireGuard) | Accès d'administration distant chiffré sans exposition publique |
| **Station d'Analyse** | REMnux / Kali Linux | Environnement sécurisé isolé avec Ghidra |

---

## 2. Procédure d'installation

### Étape 1 — Préparation de l'environnement Debian

Mise à jour du système et installation des paquets prérequis :

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl ufw
```

### Étape 2 — Résolution des conflits de ports natifs

Par défaut, certains services système Debian occupent des ports requis par les sondes de T-Pot (ports 25, 53 et 5355). Leur libération est obligatoire pour éviter le crash en boucle du conteneur d'initialisation (`tpotinit`) :

```bash
# 1. Arrêt et désactivation du serveur mail local (port 25)
sudo systemctl stop exim4
sudo systemctl disable exim4

# 2. Désactivation du résolveur local systemd-resolved (ports 53 et 5355)
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# 3. Configuration statique des serveurs de noms
sudo rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

### Étape 3 — Récupération du dépôt T-Pot

Clonage du dépôt officiel puis passage dans le répertoire du projet :

```bash
git clone https://github.com/telekom-security/tpotce
cd tpotce
ls
```

![Arborescence du dépôt cloné](images/03_cd_tpotce_ls.png)
*Figure 1 : Contenu du dépôt officiel T-Pot CE cloné sur la machine hôte.*

### Étape 4 — Lancement de l'installation

Exécution du script d'installation :

```bash
./install.sh
```

Le script demande ensuite de choisir le type d'installation :

![Choix du type d'installation](images/04_install_type_prompt.png)
*Figure 2 : Sélection du mode d'installation HIVE/Standard.*

* **(H)ive** — Installation T-Pot Standard / HIVE : inclut tout le nécessaire pour un déploiement complet avec WebUI, Elasticsearch et Kibana.
* **(S)ensor** — Installation T-Pot Sensor : optimisée pour un déploiement distribué déporté.
* **(M)obile** — Installation T-Pot Mobile.

---

## 3. Configuration du pare-feu (UFW), Cloisonnement & VPN Tailscale

### 3.1. Règles UFW initiales

Pour isoler l'administration du serveur des honeypots exposés publiquement, les ports d'administration sont strictement filtrés par adresse IP source :

| Port | Usage |
| :--- | :--- |
| `64294/TCP` | Port de secours / Web administration Cockpit |
| `64295/TCP` | SSH d'administration de l'hôte (déplacé par T-Pot) |
| `64297/TCP` | Interface Web de visualisation (Kibana / T-Pot Web) |
| `1:64000` (TCP/UDP) | Ports d'écoute des honeypots ouverts au web |

```bash
# 1. Politiques par défaut
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 2. Restriction des ports d'administration à l'IP de gestion
export MY_IP="VOTRE_IP_PUBLIQUE"
sudo ufw allow from $MY_IP to any port 64294 proto tcp comment 'T-Pot Management'
sudo ufw allow from $MY_IP to any port 64295 proto tcp comment 'T-Pot SSH'
sudo ufw allow from $MY_IP to any port 64297 proto tcp comment 'T-Pot Web Kibana'

# 3. Exposition des pièges au trafic Internet
sudo ufw allow 1:64000/tcp comment 'Honeypots TCP'
sudo ufw allow 1:64000/udp comment 'Honeypots UDP'

# 4. Activation
sudo ufw enable
```

Vérification de la configuration active :

```bash
sudo ufw status
```

![Statut du pare-feu UFW](images/01_ufw_status.png)
*Figure 3 : Filtrage strict des ports d'administration réservés à l'IP de management.*

### 3.2. Mobilité et accès distant via VPN maillé (Tailscale)

Afin de pouvoir administrer le système et consulter le tableau de bord Kibana depuis n'importe quel réseau (réseau étudiant/scolaire, mobilité 4G/5G) sans devoir modifier continuellement l'IP autorisée dans UFW, une liaison maillée **Tailscale** a été mise en place.

1. **Installation sur le VPS Debian :**
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```

2. **Vérification du maillage point à point :**

![Statut du réseau Tailscale](images/tailscale_connected_nodes.png)
*Figure 4 : Appairage réussi du VPS hôte (`vmi3593660` - 100.77.136.111) et de la station cliente (`desktop-uqv01ti` - 100.117.136.22).*

3. **Cloisonnement sur l'interface virtuelle :**
   Une interface réseau chiffrée dédiée `tailscale0` est instanciée :
   ```bash
   sudo ufw allow in on tailscale0 to any port 64297 proto tcp comment 'Kibana Tailscale'
   sudo ufw allow in on tailscale0 to any port 64295 proto tcp comment 'SSH Tailscale'
   ```

L'accès s'effectue ensuite de manière sécurisée et chiffrée via : `https://100.77.136.111:64297`.

---

## 4. Vérification et supervision des conteneurs

Contrôle de l'état des conteneurs via Docker :

```bash
sudo docker ps
```

![Conteneurs Docker actifs](images/02_docker_ps.png)
*Figure 5 : Supervision des conteneurs T-Pot en cours d'exécution (statut healthy).*

Accès au portail de visualisation global T-Pot :

![Carte interactive globale des attaques T-Pot](images/tpot_world_map_live.jpg)
*Figure 6 : Visualisation cartographique globale en temps réel des flux hostiles interceptés.*

---

## 5. Analyse de la télémétrie des cyberattaques

Après plusieurs jours d'exposition directe sur Internet sans filtrage en amont, la volumétrie globale a atteint **162 823 événements enregistrés sur une seule fenêtre de 24 heures**.

![Tableau de bord général Kibana T-Pot](images/kibana_dashboard_overview_162k.jpg)
*Figure 7 : Vue générale du tableau de bord Elastic/Kibana affichant les 162 823 événements.*

### 5.1. Volumétrie globale et répartition par honeypot

| Sonde (Honeypot) | Protocole émulé | Événements (24h) | Part de trafic |
| :--- | :--- | :--- | :--- |
| **Sentrypeer** | SIP / VoIP (UDP/TCP 5060) | **135 605** | ~83.3 % |
| **Cowrie** | SSH / Telnet (TCP 22, 23) | **13 155** | ~8.1 % |
| **Dionaea** | SMB / RPC / SQL (445, 135, 3306) | **11 253** | ~6.9 % |
| **Honeytrap** | Connexions réseau génériques | 825 | ~0.5 % |
| **Ddospot** | NTP / SSDP / DDoS amplification | 729 | < 0.5 % |
| **Tanner** | Attaques applicatives Web (SQLi, RCE) | 392 | < 0.3 % |
| **ConPot** | Systèmes industriels (SCADA/ICS) | 161 | < 0.1 % |

![Histogrammes et répartition par destination port et honeypot](images/kibana_histograms_ports_honeypots.jpg)
*Figure 8 : Distribution des attaques par ports de destination, sondes et répartition OS p0f.*

#### Observations clés :

* **Le pic massif Sentrypeer (VoIP) :** Un assaut coordonné d'environ **92 861 requêtes SIP** a été intercepté à 09h30, provenant d'un groupe restreint de seulement 11 adresses IP sources uniques. Cela matérialise une campagne agressive de découverte de PBX/passerelles téléphoniques pour de la fraude aux appels surtaxés (*toll fraud*).

![Pic massif d'attaques SIP à 09h30](images/kibana_attack_histogram_spike_92k.png)
*Figure 9 : Pic de 92 861 requêtes concentré sur 11 adresses IP sources uniques.*

* **Sollicitation soutenue de Dionaea :** 11 253 connexions ciblant en priorité `smbd` (port 445) et `epmapper` (port 135).

![Répartition des protocoles capturés par Dionaea](images/dionaea_protocols_breakdown.png)
*Figure 10 : Prédominance écrasante du protocole SMB (`smbd`) parmi les cibles de Dionaea.*

### 5.2. Profilage géographique et dynamique spatiale

![Cartographie dynamique des flux hostiles](images/kibana_attack_map_dynamic.png)
*Figure 11 : Densité mondiale des vecteurs d'attaque reçus par le honeypot.*

* **Top pays sources :** États-Unis (culminant à 81 % lors de la rafale SIP), Bulgarie, Allemagne, Russie, Viêt Nam et Philippines.

<p align="center">
  <img src="images/attacks_by_country_us_81.png" width="48%" alt="Attaques par pays - US dominant" />
  <img src="images/attacks_by_country_bulgaria_split.png" width="48%" alt="Attaques par pays - Répartition Bulgarie et Europe" />
</p>
*Figure 12 : Analyse de la répartition par pays d'origine (surconsommation US lors du pic SIP vs répartition européenne diffuse).*

* **Typologie et réputation des sources :** La réputation IP (`Attacker Src IP Reputation`) indique plus de 90 % d'adresses étiquetées comme *mass scanner* ou *known attacker*.
* **Empreintes TCP/OS (p0f) :** Prédominance de paquets forgés par des systèmes Linux récents/embarqués et des signatures historiques Windows NT.

### 5.3. Tentatives d'intrusion par force brute (Cowrie)

Sur le honeypot SSH/Telnet **Cowrie**, l'activité oscille continuellement entre les ports 22 et 23 :

![Histogramme temporel des flux entrants Cowrie SSH et Telnet](images/cowrie_ssh_telnet_histogram.png)
*Figure 13 : Activité comparée des tentatives d'intrusion SSH vs Telnet sur Cowrie.*

#### Dictionnaires d'identifiants et de mots de passe :

![Nuages de mots-clés utilisateurs et mots de passe](images/kibana_tagcloud_credentials.jpg)
*Figure 14 : Nuages de mots-clés des identifiants et mots de passe injectés par brute-force.*

* **Comptes ciblés :** `root` (ultra-majoritaire), `admin`, `postgres`, `mysql`, `deploy`, `devops`, `student`.
* **Mots de passe récurrents :** `123456`, `(empty)` (mot de passe vide), `password`, `1234`, `root`, `admin123`.

#### Commandes post-authentification interceptées :

Dès l'ouverture d'une session interactive factice, les scripts malveillants déroulent une routine de reconnaissance matérielle :

![Commandes post-exploitation saisies sur Cowrie](images/cowrie_input_top10_commands.png)
*Figure 15 : Top 10 des commandes de profilage système exécutées sur Cowrie.*

```bash
uname -s -v -n -r -m
uname -a
system
uname -s -v -n -m 2 > /dev/null || ...
```

Ces séquences caractérisent les injecteurs de botnets DDoS (familles Mirai, Gafgyt) cherchant à déterminer l'architecture CPU (x86_64, ARM, MIPS, SH4) afin de télécharger le binaire ELF approprié.

---

## 6. Analyse de malwares et Reverse Engineering (Dionaea + Ghidra)

Contrairement à Cowrie qui capture des scripts shell Linux, la sonde **Dionaea** a intercepté plusieurs binaires exécutables Windows via le protocole SMB (port 445).

### 6.1. Extraction et qualification des charges utiles

Localisation sur l'hôte : `/home/user/tpotce/data/dionaea/binaries/`.

![Extraction des binaires dans Dionaea](images/dionaea_binaries_file_permission.png)
*Figure 16 : Identification des charges utiles interceptées par Dionaea sur le système hôte.*

L'exécution avec privilèges administratifs (`sudo file *`) confirme la présence d'exécutables Windows :
```bash
sudo file *
# Résultat : PE32 executable (DLL) Intel 80386, for MS Windows
```

Un échantillon nommé d'après son hash MD5 (`0ab2aeda90221832167e5127332dd702`) a été isolé et transféré vers l'environnement d'analyse (REMnux) :

```bash
scp -P 64295 root@100.77.136.111:/home/user/tpotce/data/dionaea/binaries/0ab2aeda90221832167e5127332dd702 ./sample.bin
```

### 6.2. Analyse statique et désassemblage sous Ghidra

L'échantillon a été importé dans **Ghidra** au sein d'un projet dédié :

![Projet Ghidra et importation du binaire](images/ghidra_project_sample_bin.png)
*Figure 17 : Initialisation du projet d'ingénierie inverse dans Ghidra.*

Après lancement de l'analyse automatique, le panneau de décompilation reconstitue le code C de la fonction d'entrée (`entry`) :

![Décompilation initiale du point d'entrée](images/ghidra_entry_decompile_view.png)
*Figure 18 : Décompilation de la routine d'entrée du binaire.*

#### A. Détection des artefacts textuels (Defined Strings)

L'exploration des chaînes de caractères définies révèle deux noms explicites :

1. `mssecsvc.exe` : Exécutable ciblé par la routine.
2. `launcher.dll` : Nom interne d'origine de la DLL analysée.

<p align="center">
  <img src="images/ghidra_strings_mssecsvc.png" width="48%" alt="Chaîne mssecsvc.exe identifiée" />
  <img src="images/ghidra_strings_launcher_dll.png" width="48%" alt="Chaîne launcher.dll identifiée" />
</p>
*Figure 19 : Extraction des artefacts critiques démontrant la présence de la chaîne d'infection WannaCry.*

Ces identifiants démontrent formellement qu'il s'agit du composant d'injection du ver **WannaCry (WanaCrypt0r 2.0)**, historiquement associé à la porte dérobée de niveau noyau **DoublePulsar** injectée après exploitation de la vulnérabilité SMB **EternalBlue** (MS17-010).

#### B. Analyse du point d'entrée et de la table d'exportation

Dans le **Symbol Tree** > **Exports**, le binaire n'expose qu'une seule fonction publique spécifique :

* **Nom de l'export :** `PlayGame` (nom délibérément inscrit par les auteurs de WannaCry).

Cette fonction est invoquée par l'exploit DoublePulsar une fois la DLL injectée au sein du processus système critique `lsass.exe`.

#### C. Rétro-ingénierie de la fonction d'extraction (`FUN_10001016`)

L'étude du code C décompilé de la fonction `FUN_10001016` met en évidence le mécanisme de largage (*dropper*) du malware :

![Décompilation Ghidra de la fonction d'extraction de ressource](images/ghidra_decompiled_dropper_routine.png)
*Figure 20 : Routine d'extraction et d'écriture de la charge utile sur le disque dur.*

```c
// Code décompilé dans Ghidra (FUN_10001016)
hResInfo = FindResourceA(DAT_1000313c, (LPCSTR)0x65, &DAT_10003010);
if ((((hResInfo != (HRSRC)0x0) &&
     (hResData = LoadResource(DAT_1000313c, hResInfo), hResData != (HGLOBAL)0x0)) &&
     (pDVar1 = LockResource(hResData), pDVar1 != (DWORD *)0x0)) &&
     (DVar2 = SizeofResource(DAT_1000313c, hResInfo), DVar2 != 0)) {
  DVar2 = *pDVar1;
  hFile = CreateFileA(&DAT_10003038, 0x40000000, 2, (LPSECURITY_ATTRIBUTES)0x0, 2, 4, (HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    WriteFile(hFile, pDVar1 + 1, DVar2, &local_4, (LPOVERLAPPED)0x0);
    CloseHandle(hFile);
  }
  return 1;
}
return 0;
```

#### Décomposition analytique de la routine :

1. **Localisation de ressource interne (`FindResourceA` & `LoadResource`) :** La DLL recherche dans sa section de ressources (ressource ID `0x65` / 101) un binaire embarqué et le charge en mémoire vive.
2. **Verrouillage du tampon (`LockResource` & `SizeofResource`) :** Récupération de l'adresse mémoire du payload et de sa dimension exacte en octets.
3. **Création du fichier sur le disque (`CreateFileA`) :** Création d'un binaire dont le nom correspond à la variable `DAT_10003038` (la chaîne **`mssecsvc.exe`** identifiée plus haut).
4. **Écriture de la charge utile (`WriteFile` & `CloseHandle`) :** Les octets de la ressource sont écrits sur le disque cible, puis le handle de fichier est fermé.

Cet exécutable déposé (`mssecsvc.exe`) est ensuite démarré en tâche de fond comme faux service de sécurité Windows pour scanner le web sur le port 445 (SMB) et déclencher la phase de chiffrement.

---

## 7. Bilan de sécurité & Recommandations

1. **Isolation réseau stricte :** L'exposition directe de services sur Internet sans filtrage applicatif génère une saturation instantanée de scans hostiles. Aucun service d'administration ne doit être accessible sans tunnel VPN chiffré (Tailscale / WireGuard) ou liste blanche stricte.
2. **Obsolescence des protocoles vulnérables :** L'interception répétée de binaires WannaCry prouve que des botnets exploitent toujours activement la vulnérabilité EternalBlue (MS17-010). Le protocole SMBv1 doit être désactivé sur l'ensemble des réseaux d'entreprise.
3. **Protection des passerelles VoIP :** Le pic de 92 000 requêtes SIP met en évidence la recherche automatisée de passerelles mal configurées pour des fraudes aux numéros surtaxés, justifiant le recours à du rate-limiting et à des solutions anti-bruteforce (Fail2Ban).