# fireflux

Création d'une matrice de flux à partir d'un firewall

## Comment installer ?

- Cloner le repository

- Installer les requirements `pip install -r requirements.txt`

- Lancer le programme `python ./main.py`

## Comprendre le Code

- Lire le main.py

- Comprendre les objets et leurs fonctions

- Si vous êtes cons allez regarder le schéma sur Discord

# Fireflux CLI design

## Endpoints

Endpoints can be either HTTP or file paths

### HTTP endpoints

When we want to interact with firewall servers, we use a URL. The username and
password can be included in the access point URL encoded using the HTTP Basic Auth format. We could add a more secure way
to enter the password by using a secure prompt.

`pfsense+http://YWRtaW46cGZzZW5zZQ@10.37.129.2`

### File endpoints

When we want to interact with local files, we use regular file system paths,
with the file type taken from the path.

`rules.csv` or `rules.json`

## Supported features

- Pull rules: `fireflux SENSE+http://TOKEN@0.0.0.0/ rules.json`
- Push rules: `fireflux rules.json SENSE+http://TOKEN@0.0.0.0/`
- Copy rules:
  `fireflux SENSE+http://TOKEN@0.0.0.0/ SENSE+http://TOKEN@0.0.0.1/`
- Translate rules files: `fireflux rules.json rules.csv`
- Visualize rules from server: `fireflux SENSE+http://TOKEN@0.0.0.0/`
- Visualize rules from file: `fireflux rules.csv`

## Current help message

```
Usage: cli.py [OPTIONS] SRC [DST]

  Cross platform firewall rules tool

Options:
  --help  Show this message and exit.
```

## Open questions

- Can we detect the type of firewall elegantly from its url?
- Can we enter the password more securely?

## TODO 

- Excel format
- Auth prompt
- Better error handling
- Automatic backup ?