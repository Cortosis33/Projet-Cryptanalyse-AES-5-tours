# Projet-Cryptanalyse-AES-5-tours

## Structure du code

Le code est structurer comme suit :
* `src` : c'est ici que se trouve l'implémentation du chiffrement AES ainsi, qu'un fichier contenant du code commun aux attaques.
* `include` : ici, se trouve tous les fichiers `.h` des fichiers `.c`
* `attacks` : dans ce dossier se trouve les deux attaques implémentés (pour yoyo, il y a deux implémentations basé sur le même algorithme mais codé différemment)

## Parametres

### Square

Pour l'attaque Square, vous pouvez tester les deux types d'attaques. Pour cela, il vous suffit de modifier la constante dans le fichier `attacks/square/square_test.c`:

```c
#define TYPE 1
```

ou

```c
#define TYPE 2
```

Par défaut, l'attaque s'effectuera sur une clé aléatoire. Si vous changer ce parametre :

```c
#define RANDOM 1
```

la clé par défaut deviendra `K0`

### Yoyo

De meme que pour l'attaque Square, l'attaque s'effectuera sur une clé aléatoire.

## Execution du code

Pour executer l'attaque Square, il vous suffit de faire :

```bash
cd attack/square
make
./square_test
```

Pour l'attaque yoyo, les commandes sont les memes :

```bash
cd attack/yoyo
make
./yoyo_test
```
