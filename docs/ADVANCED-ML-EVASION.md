# Stratégies d'Évasion Avancées contre le Machine Learning

Ces stratégies représentent le summum de la technologie d'évasion, conçues spécifiquement pour tromper les classifieurs de trafic basés sur l'apprentissage automatique (
Machine Learning). Elles ne se contentent pas d'imiter un comportement légitime, mais cherchent activement à introduire du "bruit" et de l'entropie pour rendre la
classification statistique impossible.

### Histoire et Contexte

La recherche sur l'utilisation de l'IA pour la sécurité réseau a explosé dans les années 2010. Des entreprises de cybersécurité comme Darktrace, Vectra AI ou Palo Alto
Networks ont mis sur le marché des produits basés sur la détection d'anomalies. Ces systèmes ne se basent plus sur des signatures fixes, mais sur des modèles statistiques
de trafic. Un article fondateur de l'Université de Californie, Berkeley, intitulé "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection" a
mis en évidence à la fois le potentiel et les limites de ces approches.

La contre-recherche, connue sous le nom d'"Adversarial Machine Learning", a rapidement émergé. Des chercheurs du MIT et de Google ont démontré qu'il était possible de
créer des "exemples adverses" (adversarial examples) : des entrées subtilement modifiées qui provoquent une erreur de classification de la part du modèle d'IA. Ces
stratégies s'inspirent de ces travaux en appliquant les principes de l'apprentissage machine adverse au scan de réseau. L'objectif est de maximiser l'entropie et la
confusion pour que le trafic de scan tombe dans une "zone grise" que le classifieur ne peut pas identifier de manière fiable.

### 1. `adaptive-learning-evasion`

* **Objectif** : Utiliser une combinaison de techniques pour s'adapter et déjouer les systèmes qui apprennent en continu.
* **Paramètres Clés** :
    * `scan_type: "fin"` : Commence par un type de scan intrinsèquement plus furtif qu'un scan SYN.
    * `timing_pattern: "fibonacci"` : Un modèle complexe mais pas entièrement chaotique, qui peut déjouer les modèles statistiques simples.
    * `fragment: true` et `padding: 48` : Combine la fragmentation avec un rembourrage de taille moyenne pour augmenter la complexité des paquets.
    * `decoys: 35` : Un nombre élevé de leurres pour augmenter le bruit statistique.

### 2. `ml-classifier-confusion`

* **Objectif** : Créer le trafic le plus chaotique et le plus riche en entropie possible pour faire échouer le processus de "feature engineering" du modèle d'IA.
* **Paramètres Clés** :
    * `timing_pattern: "random"` : Un timing totalement imprévisible.
    * `padding: 96` : Un rembourrage très important pour maximiser l'entropie de chaque paquet.
    * `decoys: 45` : Un nombre très élevé de leurres pour rendre l'attribution et la corrélation extrêmement difficiles.
    * `os_fingerprint: "android"` : Le choix d'une empreinte mobile, combiné à un comportement de scan agressif, crée un profil contradictoire qui peut confondre un
      classifieur.

### 3. `ultra-stealth-ai-evasion`

* **Objectif** : Combiner le maximum de techniques d'évasion pour créer la stratégie la plus furtive et la plus complexe possible.
* **Paramètres Clés** :
    * `scan_type: "fin"` : Utilise un scan furtif par défaut.
    * `decoys: 40` : Un grand nombre de leurres.
    * `fragment: true` et `padding: 64` : Fragmentation et rembourrage importants.
    * `timing_pattern: "random"` : Timing chaotique.
    * `randomize_ttl: true` : Rend le traçage de la source par analyse du TTL presque impossible.
    * `fake_uptime_days: 200` : Simule un serveur avec une très longue disponibilité, ajoutant une couche de légitimité apparente.
