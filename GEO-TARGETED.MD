# Stratégies d'Évasion Géo-Ciblées

Ces stratégies sont conçues pour contourner les systèmes de censure et de surveillance nationaux, souvent appelés "Grands Pare-feu" (Great Firewalls). Chaque pays ayant
des technologies et des politiques de filtrage différentes, ces stratégies utilisent des techniques spécifiques pour se fondre dans le trafic local ou exploiter des
faiblesses connues.

### Histoire et Contexte

Le concept de censure de l'Internet à l'échelle nationale a été popularisé par le "Grand Pare-feu de Chine" (GFW). Des reportages du *New York Times* et de *Reuters* ont
largement documenté ses capacités de Deep Packet Inspection (DPI), de blocage de DNS et d'injection de paquets RST. De même, des pays comme la Russie, l'Iran et d'autres
ont développé leurs propres systèmes (par exemple, le système russe SORM), chacun avec ses particularités.

Des chercheurs d'universités comme l'Université de Toronto (Citizen Lab) et l'Université de Californie à Berkeley publient régulièrement des études sur les mécanismes de
ces pare-feu. Leurs travaux ont révélé que ces systèmes ciblent des protocoles spécifiques, des ports non standards, et sont particulièrement sensibles aux volumes de
trafic et aux modèles de communication inhabituels. Ces stratégies s'inspirent directement de ces recherches pour passer sous le radar.

---

### 1. `chinese-great-firewall-evasion`

* **Objectif** : Contourner le Grand Pare-feu de Chine, l'un des systèmes de censure les plus sophistiqués au monde.
* **Paramètres Clés** :
    * `os_fingerprint: "android"` : Le trafic mobile Android est prédominant en Chine, ce qui en fait une excellente couverture.
    * `delay: 5.0` et `timing_pattern: "random"` : Le GFW est très sensible aux scans rapides. Un délai très long et aléatoire est crucial pour éviter la détection
      comportementale.
    * `fragment: true` et `padding: 128` : La fragmentation et l'ajout d'une grande quantité de données aléatoires (padding) peuvent perturber les moteurs DPI qui
      s'attendent à des paquets bien formés.
    * `decoys: 50` : Un grand nombre de leurres pour noyer le trafic de scan réel dans un flot de connexions apparemment légitimes.
    * `src_ports: [443, 8443, 9443]` : Utilise des ports couramment associés au trafic HTTPS et à des applications populaires comme WeChat, qui sont moins susceptibles
      d'être bloqués.

---

### 2. `russian-dpi-bypass`

* **Objectif** : Déjouer les systèmes de DPI russes (comme SORM) qui ciblent activement certains services comme Telegram.
* **Paramètres Clés** :
    * `os_fingerprint: "windows10"` : Le trafic de bureau Windows est très courant en Russie.
    * `timing_pattern: "sine"` : Un modèle de temporisation plus doux qui peut aider à éviter les seuils d'alerte basés sur des rafales de trafic.
    * `src_ports: [443, 5222, 8888]` : Inclut les ports utilisés par Telegram et VK (VKontakte), des applications populaires en Russie. Le trafic vers ces ports peut être
      considéré comme normal.
    * `fragment: true` et `padding: 64` : Techniques de fragmentation et de rembourrage pour compliquer l'analyse par les systèmes DPI.
    * `fake_uptime_days: 60` : Simule un poste de travail stable, typique d'un environnement de bureau.
