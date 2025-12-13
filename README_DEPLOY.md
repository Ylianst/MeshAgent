# 🚀 Guide de Compilation et Déploiement - Agent MeshCentral Custom

## 📋 Pré-requis

### Sur ta machine Windows :
- Visual Studio 2022 avec MSVC v140 et Windows SDK 10.0.19041.0
- Client SSH (OpenSSH inclus dans Windows 10/11)
- Clés SSH configurées pour connexion sans mot de passe :
  ```cmd
  ssh-keygen -t ed25519
  ssh-copy-id rocky@141.145.194.69
  ```

### Sur le serveur Linux (141.145.194.69) :
- MeshCentral installé dans `/opt/meshcentral/`
- Accès sudo pour l'utilisateur `rocky`
- Service `meshcentral` configuré

---

## 🔨 Option 1 : Compilation Simple

Pour compiler sans déployer :

```cmd
build_agent.bat
```

**Résultat :** `Release\MeshService64.exe`

---

## 🚀 Option 2 : Compilation + Déploiement Automatique (Recommandé)

Pour compiler ET déployer automatiquement sur le serveur :

```cmd
build_and_deploy.bat
```

### Étapes exécutées :
1. ✅ Compilation de l'agent avec corrections UAC/lock screen
2. ✅ Vérification des erreurs de compilation
3. ❓ Demande de confirmation pour déploiement
4. ✅ Transfert SCP vers le serveur
5. ✅ Installation dans `/opt/meshcentral/meshcentral-data/agents/`
6. ✅ Redémarrage de MeshCentral → **Signature automatique**

---

## 🔐 Signature Automatique par MeshCentral

Quand tu déploies l'agent, **MeshCentral fait automatiquement** :

1. Détecte le nouveau binaire `MeshService64.exe`
2. Génère un certificat de signature (si pas déjà existant)
3. Signe l'agent → crée `signedagents/meshagent-signed`
4. Les nouvelles installations utiliseront l'agent signé

### Vérifier la signature :

```bash
ssh rocky@141.145.194.69
ls -lh /opt/meshcentral/meshcentral-data/signedagents/
```

Tu devrais voir des fichiers comme :
- `meshagent-linux-x86-64-signed`
- `MeshService64.exe` (Windows x64)

---

## 🔄 Mise à Jour des Agents Existants

Après déploiement, pour forcer les appareils connectés à se mettre à jour :

### Via l'interface MeshCentral :
1. Aller dans **My Devices**
2. Sélectionner les appareils Windows
3. **Actions** → **Update Agent**

### Via ligne de commande (sur l'appareil) :
```cmd
cd "C:\Program Files\Mesh Agent"
.\MeshAgent.exe -update
```

---

## 🐛 Dépannage

### Erreur : "The Windows SDK version 8.1 was not found"
**Solution :** Les fichiers `.vcxproj` ont été mis à jour pour utiliser SDK 10.0.19041.0

### Erreur SCP : "Permission denied"
**Solution :** Configure tes clés SSH :
```cmd
ssh-keygen -t ed25519 -C "ton@email.com"
ssh-copy-id rocky@141.145.194.69
ssh rocky@141.145.194.69  # Test connexion
```

### L'agent ne se met pas à jour automatiquement
**Cause :** MeshCentral compare les hashes des fichiers  
**Solution :** Change la version dans le code ou force l'update via l'interface

---

## 📝 Fichiers Modifiés (Correctifs UAC/Lock Screen)

### `meshcore/KVM/Windows/kvm.c`
- **Fonction `CheckDesktopSwitch()`** : Adapte le desktop au lieu de shutdown
- **Variable `g_currentDesktop`** : Tracking du desktop handle actif
- **Refresh forcé** : Après changement de desktop

### `meshservice/ServiceMain.c`
- Gestion propre des événements de session Windows

### Fichiers projet (`.vcxproj`)
- SDK Windows : `8.1` → `10.0.19041.0`

---

## 🎯 Résultat Attendu

Après déploiement, ton agent custom :
- ✅ **Ne se déconnecte plus** lors de popups UAC
- ✅ **Continue de capturer l'écran** sur le lock screen
- ✅ **S'adapte automatiquement** aux changements de session
- ✅ **Est signé automatiquement** par MeshCentral

---

## 📞 Support

Si tu rencontres des problèmes :
1. Vérifie les logs de compilation
2. Teste la connexion SSH : `ssh rocky@141.145.194.69`
3. Vérifie les logs MeshCentral : `sudo journalctl -u meshcentral -f`
