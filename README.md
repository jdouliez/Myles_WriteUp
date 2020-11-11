
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

### Conclusion
Après avoir forcé notre entrée dans la machine, on constate bien que la machine de Myles a été compromise.
Cependant, nous n'avons pas réussi à déterminer les causes puisque le pirate/malware semble avoir bien caché ses traces.
> Red Team 1 - 0 Blue Team

A charge de revanche.
