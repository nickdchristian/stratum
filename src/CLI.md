# `sto`

Strato: AWS Auditor

**Usage**:

```console
$ sto [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.

**Commands**:

* `s3`: S3 Audit Commands

## `sto s3`

S3 Audit Commands

**Usage**:

```console
$ sto s3 [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `security`: S3 Security Audits

### `sto s3 security`

S3 Security Audits

**Usage**:

```console
$ sto s3 security [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run ALL S3 Security checks.
* `encryption`: Scan for Encryption configuration.
* `public-access`: Scan for Public Access Block configuration.
* `policy`: Scan for Bucket Policy compliance (SSL &amp;...
* `acls`: Scan for Legacy ACL usage and Log Delivery...
* `versioning`: Scan for Versioning and MFA Delete...
* `object-lock`: Scan for Object Lock configuration.
* `naming`: Scan for Predictable Bucket Names (Entropy...
* `website`: Scan for Static Website Hosting...

#### `sto s3 security all`

Run ALL S3 Security checks.

**Usage**:

```console
$ sto s3 security all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`: Exit code 1 if risks found
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security encryption`

Scan for Encryption configuration.

**Usage**:

```console
$ sto s3 security encryption [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.

#### `sto s3 security public-access`

Scan for Public Access Block configuration.

**Usage**:

```console
$ sto s3 security public-access [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.

#### `sto s3 security policy`

Scan for Bucket Policy compliance (SSL &amp; Public permissions).

**Usage**:

```console
$ sto s3 security policy [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.

#### `sto s3 security acls`

Scan for Legacy ACL usage and Log Delivery compliance.

**Usage**:

```console
$ sto s3 security acls [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.

#### `sto s3 security versioning`

Scan for Versioning and MFA Delete configuration.

**Usage**:

```console
$ sto s3 security versioning [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.

#### `sto s3 security object-lock`

Scan for Object Lock configuration.

**Usage**:

```console
$ sto s3 security object-lock [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.

#### `sto s3 security naming`

Scan for Predictable Bucket Names (Entropy check).

**Usage**:

```console
$ sto s3 security naming [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.

#### `sto s3 security website`

Scan for Static Website Hosting configuration.

**Usage**:

```console
$ sto s3 security website [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`
* `--json`
* `--csv`
* `--failures-only`
* `--org-role TEXT`
* `--help`: Show this message and exit.
