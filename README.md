# 🖥️ Outil de maintenance Windows

![Version](https://img.shields.io/badge/version-v3.5.0-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Une puissante boîte à outils de maintenance Windows tout-en-un, entièrement conçue avec Batch et Powershell. 
Conçue pour les utilisateurs expérimentés, les administrateurs système et les bricoleurs curieux, elle est désormais plus intelligente, plus sûre et entièrement compatible hors ligne.

J'ai ajouter du code personnel, des nouvelles options...

Je ne me suis pas attardé sur l'esthétique du script... Suite à la traduction, il se pourra que certains menu ne soient pas alignés correctement..

Traduction en Français de : https://github.com/ios12checker/Windows-Maintenance-Tool/

La traduction n'est pas encore complète !

---

## 📸 Capture d'écran

<img width="1219" height="832" alt="powershell_XjTFD9ZWA8" src="https://github.com/user-attachments/assets/73d11d4d-0fed-4db4-8362-8937c7e715c6" />

---

## ✅ Caractéristiques

**Exécuter les outils de réparation essentiels :**
- Accès rapide à SFC, DISM et CHKDSK pour les réparations Windows essentielles

**Optimisation des disques SSD :**
- TRIM et défragmentation compatible pour des disques plus rapides et plus sains
ional winget)

**Gestion des mises à jour Windows** :
- Utilisez winget pour installer, mettre à niveau et réparer les packages système
- NOUVEAU : Installe automatiquement winget s'il est manquant !
- Gestion flexible des packages : Affichez, recherchez et mettez à niveau des applications/packages individuels en saisissant directement leur identifiant.

**Diagnostic et réparation réseau** :
- Inclut ipconfig, la visualisation des tables de routage, la configuration DNS, la réinitialisation de l'adaptateur, et bien plus encore.

**Nettoyage de la confidentialité et des fichiers temporaires** :
- Nettoie les fichiers temporaires, les journaux et le cache du navigateur.
- NOUVEAU : Nettoyage de la confidentialité pour les traces supplémentaires (historique, cookies, etc.).

**Enregistrez des rapports détaillés** :
- Exportez les informations système, les informations réseau et la liste des pilotes vers votre bureau ou un dossier personnalisé

**Outils de registre** :
- Nettoyage, sauvegarde et analyse de corruption sécurisés
- Nettoyage de registre stable et piloté par menus :
- Liste des entrées « sûres à supprimer » (IE40, IE4Data, DirectDrawEx, etc.)
- Suppression groupée de toutes les entrées sûres
- Sauvegarde et restauration faciles grâce aux fichiers .reg versionnés

**Gestion DNS-Adblock** :
- Bloquez les domaines publicitaires et traqueurs avec le fichier hosts (adblock et miroirs inclus)
- Améliorations : Gestion des fichiers verrouillés, messagerie améliorée, sauvegardes/restaurations multiples

**Gestionnaire de pare-feu (NOUVEAU !) :**
- Gestionnaire de pare-feu PowerShell intégré, piloté par menus
- Gestion des règles de pare-feu, activation/désactivation du pare-feu Windows, directement depuis l'outil — aucun logiciel externe requis

**Gestion des tâches et des pilotes :**
- Affichage et réparation des tâches planifiées
- Liste et exportation de tous les pilotes installés

**Menu convivial et convivial :**
- Toutes les fonctions sont accessibles depuis un menu principal clair — aucune expérience PowerShell requise
- Assistance/aide, contact Discord/GitHub, accessible d'une simple pression sur une touche

**Portable et sécurisé :**
- Fonctionne sur USB, aucune installation ni déploiement administrateur requis
- Aucune dépendance tierce ni téléchargement internet requis (sauf winget en option)
---

## ⚙️ Installation

1. Démarrez le fichier `Start_Windows_Maintenance_Tool.bat`.
2. Suivez le menu interactif.
3. Assurez-vous que les fichiers `Start_Windows_Maintenance_Tool.bat` et `Windows_Maintenance_ToolWindows_Maintenance_Tool_French.ps1` se trouvent dans le même dossier, sinon l'outil de maintenance ne démarrera pas correctement.

> ⚠️ Le script s'affichera qu'en Français. C'est normal.

---

## 📁 Fichiers de sortie

Enregistré directement dans le dossier de votre choix (par défaut : Bureau\RapportsSystème) :

- `System_Info_YYYY-MM-DD.txt`
(Rapport complet des informations système)

- `Network_Info_YYYY-MM-DD.txt`
(Configuration réseau détaillée)

- `Driver_List_YYYY-MM-DD.txt`
(Liste de tous les pilotes installés)

- `routing_table_YYYY-MM-DD.txt`
(Table de routage réseau)

- `RegistryBackup_YYYY-MM-DD_HH-MM.reg`
(Fichiers de sauvegarde du registre, avec date et heure)
---

## 🧪 Dépannage et FAQ

<code style="color : red">Q</code> : Le script ne s’est pas exécuté avec les droits d’administrateur ? br / >
R : Vous n'avez rien à faire, le script se relancera automatiquement en Administrateur br / > br / >

Si vous souhaitez exécuter le script PowerShell manuellement, utilisez cette commande depuis une fenêtre PowerShell avec privilèges élevés : br / >
```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File 'Chemin\vers\Windows_Maintenance_Tool.ps1'"
```
Q : Pourquoi l'outil plante-t-il lors de la sélection du nettoyage du registre ? br / >
R : Ce problème a été entièrement résolu dans la version 3.1.3. L'outil répertorie et supprime désormais les clés de registre en toute sécurité via PowerShell. br / >
Avant toute suppression, une sauvegarde est automatiquement créée et les erreurs sont correctement gérées pour éviter les plantages de script ou les pertes de données accidentelles. br / > br / >

**Q : Pourquoi la défragmentation du registre a-t-elle été supprimée ?** br / >
R : Cette fonctionnalité dépendait d'un outil tiers (NTREGOPT) qui n'est plus accessible. br / >
Le script est désormais entièrement hors ligne et natif de Windows. br / > br / >

---

## 🤝 Contribuer

Les demandes d'extraction, les problèmes et les commentaires sont les bienvenus !
Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les instructions.

## 🌐 Remerciements aux médias et à la communauté

Un grand merci à tous ceux qui ont partagé, commenté ou écrit sur l'outil de maintenance Windows !
Vos articles, mentions et commentaires permettent à davantage d'utilisateurs de découvrir et d'exploiter ce projet.

Remerciements spéciaux à :**

- [Korben.info – Script de réparation Windows automatique](https://korben.info/script-reparation-windows-automatique.html)
- [Phonandroid.com – Gagnez un temps fou sur Windows 11 avec ce nouvel outil gratuit…](https://www.phonandroid.com/gagnez-un-temps-fou-sur-windows-11-avec-ce-nouvel-outil-gratuit-qui-repare-et-optimise-votre-pc.html)
- [Ghacks – Windows Maintenance Tool: one-click access to Windows repairs and optimizations](https://www.ghacks.net/2025/06/11/windows-maintenance-tool-one-click-access-to-windows-repairs-and-optimizations/)
- [PCWorld – This free all-in-one tool fixes common Windows problems](https://www.pcworld.com/article/2809221/this-free-all-in-one-tool-fixes-common-windows-problems.html)
- [Unofficial script does the most useful official Windows 11/10 repairs you want automatically](https://www.neowin.net/news/unofficial-script-does-the-most-useful-official-windows-1110-repairs-you-want-automatically/)


Merci également à Neowin et à tous les autres sites technologiques et membres de la communauté pour votre soutien et votre couverture !

Si vous avez écrit un article ou réalisé une vidéo sur ce projet, n'hésitez pas à ouvrir un ticket ou une demande pour figurer ici !

## 🎬 Guides vidéos (en anglais uniquement, je manque de temps...)

- [Windows Maintenance Tool – Guide by Info4Geek](https://www.youtube.com/watch?v=TpZY1nXHTsw)
- [Walkthrough, by ThomyPC](https://www.youtube.com/watch?v=0aUu2agaIto)
- [Showcase of Windows Maintenance Tool by Tech Enthusiast](https://www.youtube.com/watch?v=zfIQvk8BEcM)


---

## Dons pour m'offrir un café
Si vous trouvez ce projet utile et souhaitez soutenir son développement, n'hésitez pas à faire un don.
Votre soutien nous permet de maintenir l'outil de maintenance Windows gratuit et à jour pour tous.

[Donner par PayPal] (https://www.paypal.me/Lilbatti69)

Ou ajoutez simplement une étoile ⭐ au dépôt et partagez-le !
---

## 📜 License

Sous licence MIT.

Voir [`LICENSE`](LICENSE) pour plus de détails.

## 🔗 Projets connexes

- [🍎 MSS – Mac Service Script](https://github.com/ios12checker/MSS-Mac-Service-Script)
