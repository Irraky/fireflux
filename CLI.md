# Fireflux CLI design
For the CLI library, I used [click](https://click.palletsprojects.com/en/8.1.x/). I am open to simpler/better alternatives if you know any.

I think we can support all our features with a single command taking a source and a destination which I will call `endpoints`. I started to experiment with this in [cli.py](pfSense/cli.py).

## Endpoints

Endpoints can be either HTTP or file paths

### HTTP endpoints

When we want to interact with firewall servers, we use a URL. The username and password can be included in the access point URL. We could add a more secure way to enter the password by using a secure prompt.

`http://admin:pfsense@172.16.143.2:80/`

### File endpoints

When we want to interact with local files, we use regular file system paths, with the file type taken from the path.

`rules.csv` or `rules.json`

## Supported features

- Pull rules: `fireflux http://user:password@0.0.0.0/ rules.json`
- Push rules: `fireflux rules.json http://user:password@0.0.0.0/`
- Copy rules: `fireflux http://user:password@0.0.0.0/ http://user:password@1.1.1.1/`
- Translate rules files: `fireflux rules.json rules.csv`
- Visualize rules from server: `fireflux http://user:password@0.0.0.0/`
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