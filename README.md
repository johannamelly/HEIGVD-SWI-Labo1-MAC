[Livrables](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#livrables)

[Échéance](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#échéance)

[Quelques pistes importantes](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#quelques-pistes-importantes-avant-de-commencer-revenez-les-voir-vous-en-aurez-besoin-)

[Travail à réaliser](https://github.com/arubinst/HEIGVD-SWI-Labo1-MAC#travail-à-réaliser)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 MAC

__A faire en équipes de deux personnes__

### Pour cette partie pratique, vous devez être capable de :

*	Détecter si un certain client WiFi se trouve à proximité
*	Obtenir une liste des SSIDs annoncés par les clients WiFi présents

Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy et la suite aircrack pour vos manipulations. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). __Si vous utilisez une VM, il vous faudra une interface WiFi usb, disponible sur demande__.

__ATTENTION :__ Pour vos manipulations, il pourrait être important de bien fixer le canal lors de vos captures et vos injections. Si vous en avez besoin, la méthode la plus sure est d'utiliser l'option :

```--channel``` de ```airodump-ng```

et de garder la fenêtre d'airodump ouverte en permanence pendant que vos scripts tournent ou vos manipulations sont effectuées.

Pour les interfaces Alfa AWUS036ACH (interfaces noires), __il faut activer la compatibilité USB 3.0 sur votre VM__. Pour toute autre interface, il faudra utiliser USB 2.0 sur votre VM. __Les ports USB configurés en 1.0 ou 1.1 ne sont pas assez rapides pour sniffer du WiFi__.

Pour passer une interface __Alfa AWUS036H, AWUS036NH et très probablement l'interface de votre propre laptop__ en mode monitor, il faudra utiliser la commande suivante (vérifiez avec ```ifconfig```que votre interface s'appelle bien ```wlan0```. Sinon, utilisez le nom correct dans la commande):

```bash
sudo airmon-ng start wlan0
```

Vous retrouverez ensuite une nouvelle interface ```wlan0mon``` qui fonctionne en mode monitor.

Si vous utilisez les interfaces Alfa __AWUS036ACH__ (interfaces noires), il faudra faire les manipulations suivantes pour les configurer en mode monitor. __ATTENTION, utilisez les commandes suivantes uniquement si vous utilisez les interfaces AWUS036ACH__ :

### Installer le driver (disponible sur Kali. Pour d'autres distributions, il faudra probablement le compiler à partir des sources) :

```bash
sudo apt-get install realtek-rtl88xxau-dkms
```

Ensuite, pour passer en mode monitor :

### Mettre l'interface “down”

```bash
sudo ip link set wlan0 down
```

### Configurer le mode monitor

```bash
sudo iwconfig wlan0 mode monitor
```

### Si vous devez compiler le driver :

```bash
git clone https://github.com/astsam/rtl8812au.git
cd rtl8812au
make
sudo make install
```

## Quelques pistes importantes avant de commencer (revenez les voir... vous en aurez besoin) :

- Si vous devez capturer et injecter du trafic, il faudra configurer votre interface 802.11 en mode monitor.
- Python a un mode interactif très utile pour le développement. Il suffit de l'invoquer avec la commande ```python```. Ensuite, vous pouvez importer Scapy, rc4 et autres et utiliser les commandes directement dans la console (voir script fourni pour plus d'information sur l'importation de modules). En fait, vous pouvez même exécuter tout le script fourni en mode interactif !
- Scapy fonctionne aussi en mode interactif en invoquant la commande ```scapy```.  
- Dans le mode interactif, « nom de variable + <enter> » vous retourne le contenu de la variable.
- Pour visualiser en détail une trame avec Scapy en mode interactif, on utilise la fonction ```show()```. Par exemple, si vous chargez votre trame dans une variable nommée ```arp```, vous pouvez visualiser tous ces champs et ses valeurs avec la commande ```arp.show()```. Utilisez cette commande pour connaître les champs disponibles et les formats de chaque champ.
- Pour obtenir les informations du constructeur de la MAC, vous pouvez vous servir de l'API du site ```http://macvendors.co/api/xx:xx:xx:xx:xx:xx```

## Travail à réaliser

### 1. Détecter si un ou plusieurs clients 802.11 spécifiques sont à portée

Il peut être utile de détecter si certains utilisateurs se trouve dans les parages. Pensez, par exemple, au cas d'un incendie dans un bâtiment. On pourrait dresser une liste des dispositifs et la contraster avec les personnes qui ont déjà quitté le lieu.

La détection de client s'utilise également à des fins de recherche de marketing. Aux Etats Unis, par exemple, on sniffe dans les couloirs de centres commerciaux pour détecter, par exemple, quelles vitrines attirent plus de visiteurs, et quelle marque de téléphone ils utilisent. Ce service, interconnecté en réseau, peut aussi déterminer si un client visite plusieurs centres commerciaux un même jour ou sur un certain intervalle de temps.

__ATTENTION__ : Le suivi de clients iPhone n'est plus possible que dans certaines conditions depuis la version 8 d'iOS.

* Développer un script en Python/Scapy capable de capturer les trames nécessaires pour la détection de clients 802.11. Le script se lance en ligne de commandes avec comme argument une adresse MAC d'un certain client. Le script surveille ensuite les messages capturés et imprime une confirmation quand l'adresse est détectée.

__Question__ : quel type de trames sont nécessaires pour détecter les clients de manière passive ?

Les probe requests permettent de le détecter.

__Question__ : pourquoi le suivi n'est-il plus possible sur iPhone depuis iOS 8 ?

Parce que iOS randomise les adresses MAC lors de la recherche WIFI.


### 2. Clients WiFi bavards
a)	Utilisant le script que vous venez de développer comme base, faire les modifications nécessaires pour capturer les noms de réseau annoncés par les différents clients se trouvant à portée de votre scanner. 

Vous pouvez afficher les noms des réseaux avec les adresses MAC correspondantes au fur et à mesure qu'ils sont capturés mais vous devez garder une trace de quels noms correspondent à quel client. 

b)	Utiliser une ressource online pour déterminer automatiquement la marque du constructeur de l'interface WiFi pour chaque message capturé. Afficher aussi cette information avec chaque ligne imprimée.

Ainsi, à chaque fois que votre client imprime des résultats, il affiche quelque chose comme ceci :

```
00:1B:63:21:10:33 (Apple Inc.) – HEIG-VD, GVA, Lausanne, MonWiFi
00:09:18:10:23:01 (Samsung) – HEIG-VD, Marathon, europa, eduroam
```

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

- Script de détection de clients 802.11 __abondamment commenté/documenté__

- Script de détection et affichage de SSID __abondamment commenté/documenté__

-	Réponses aux éventuelles questions posées dans la donnée. Vous répondez aux questions dans votre ```README.md```

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 20 mars 2019 à 18h00
