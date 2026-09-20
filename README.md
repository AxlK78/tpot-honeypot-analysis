# Déploiement d'un Honeypot T-Pot 24.04 sur VPS

Ce projet documente le déploiement en conditions réelles du honeypot multi-services **T-Pot 24.04** sur un serveur dédié virtuel (VPS), ainsi que son durcissement réseau via pare-feu applicatif.

> **Statut du projet :** installation et durcissement réseau terminés. L'analyse de la télémétrie collectée (attaques, géolocalisation, brute-force, payloads) fera l'objet d'une prochaine mise à jour de ce document.

---

## 1. Architecture du laboratoire

| Élément | Détail |
|---|---|
| Hébergeur | Contabo (VPS Cloud) |
| Système d'exploitation | Debian 12 (Bookworm) |
| Plateforme Honeypot | T-Pot 24.04 CE (Community Edition) |
| Composants clés | Cowrie (SSH/Telnet), Dionaea, Sentrypeer (VoIP/SIP), Suricata (NIDS), suite Elastic (Elasticsearch, Kibana) |

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

![Contenu du dépôt tpotce](images/03_cd_tpotce_ls.png)
*Arborescence du dépôt cloné : `install.sh`, `docker-compose.yml`, `deploy.sh`, `genuser.sh`, etc.*

### Étape 4 — Lancement de l'installation

Exécution du script d'installation :

```bash
./install.sh
```

Le script demande ensuite de choisir le type d'installation :

![Choix du type d'installation](images/04_install_type_prompt.png)

- **(H)ive** — Installation T-Pot Standard / HIVE : inclut tout le nécessaire pour un déploiement distribué avec capteurs.
- **(S)ensor** — Installation T-Pot Sensor : optimisée pour un déploiement distribué, sans WebUI, Elasticsearch ni Kibana.
- **(M)obile** — Installation T-Pot Mobile : inclut tout le nécessaire pour exécuter T-Pot Mobile (disponible séparément).

---

## 3. Configuration du pare-feu (UFW) & cloisonnement

Pour isoler l'administration du serveur des honeypots exposés publiquement, les ports d'administration sont strictement filtrés par adresse IP source :

| Port | Usage |
|---|---|
| `64294/TCP` | Port de secours / Web administration |
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
*Seule l'IP de gestion (masquée dans le README, visible en clair sur la capture) a accès aux ports d'administration (64294, 64295, 64297) ; les honeypots (`1:64000`) restent ouverts à tout le trafic Internet, en TCP comme en UDP.*

---

## 4. Vérification et accès

### Contrôle des conteneurs Docker

```bash
sudo docker ps
```

![Conteneurs Docker actifs](images/02_docker_ps.png)
*Les conteneurs `tpotinit` et `suricata` sont opérationnels (statut `healthy`), confirmant le bon démarrage de la stack.*

### Accès au tableau de bord Kibana

```
https://<IP_DU_VPS>:64297
```

Accepter le certificat TLS auto-signé lors de la première connexion.

---

## 5. Prochaines étapes

- [ ] Laisser tourner le honeypot pour accumuler de la télémétrie
- [ ] Analyse du volume d'attaques et des sondes les plus sollicitées
- [ ] Profilage géographique et infrastructurel des attaquants
- [ ] Analyse du brute-force (identifiants/mots de passe les plus utilisés)
- [ ] Analyse technique des charges utiles (payloads, malwares interceptés)