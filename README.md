# Projet-Cryptanalyse-AES-5-tours

## Structure du code

Le code est structurer comme suit :
* `src` : c'est ici que se trouve l'implémentation du chiffrement AES ainsi, qu'un fichier contenant du code commun aux attaques.
* `include` : ici, se trouve tous les fichiers `.h` des fichiers `.c`
* `attacks` : dans ce dossier se trouve les deux attaques implémentés (pour yoyo, il y a deux implémentations)

## Parametres

### Square

Pour l'attaque Square, vous pouvez tester les deux types d'attaques. Pour cela, il vous suffit de modifier la constante dans le fichier `attacks/square/square_test.c`:

```c
#define TYPE 2
```
 ou

```c
#define TYPE 2
```

```c
#define RANDOM 1
```
