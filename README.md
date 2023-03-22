# fireflux

Manage firewall filtering rules from your terminal

## Get started

```
git clone https://github.com/Irraky/fireflux
python3 -m pip install -r requirements.txt
python3 cli.py
```

## Usage

Fireflux manipulate firewall filtering rules between on or two endpoints. These
endpoints can be files or firewall server.

### File endpoints

The following format are supported: `*.csv` and `*.json`.

### Firewall endpoint

We support `pfsense` and `opnsense`. To interact with need an ip, a http scheme
and credentials. All those informations can be merge into a single URL:

`FIREWALL_NAME+HTTP_SCHEME://AUTH_TOKEN@0.0.0.0`

When auth credential are stored inside the URL they are formatted following
[RFC7617](https://www.rfc-editor.org/rfc/rfc7617)(The 'Basic' HTTP
Authentication Scheme). If absent, auth credential are taken using a prompt.

## Usage example

- Pull rules from a PFsense firewall into a JSON file

```
fireflux pfsense+http://YWRtaW46cGZzZW5zZQ==@10.37.129.2 rules.json
```

- Push rules from a CSV file into an OPNsense firewall

```
fireflux rules.csv opnsense+http://192.168.64.17
```

- Copy rules from a PFsense firewall into an OPNsense firewall

```
fireflux SENSE+http://TOKEN@0.0.0.0/ SENSE+http://TOKEN@0.0.0.1/
```

- Translate rules stored in a JSON file into a CSV file

```
fireflux rules.json rules.csv
```

- Visualize rules from a PFsense server:

```
fireflux pfsense+http://YWRtaW46cGZzZW5zZQ==@10.37.129.2
```

- Visualize rules from csv file:

```
fireflux rules.csv
```

## TODO

- Can we detect the type of firewall elegantly from its url?
- Can we enter the password more securely? - support auth prompt
- Excel format
- Better error handling
- Automatic backup ?
