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

* `all`: Run ALL S3 Security checks (Encryption and...
* `encryption`: Scan ONLY for default encryption...
* `public-access`: Scan ONLY for public access blocks.
* `acls`: Scan ONLY for Legacy ACL usage and Log...
* `versioning`: Scan for Versioning and MFA Delete...
* `object-lock`: Scan for Object Lock configuration.

#### `sto s3 security all`

Run ALL S3 Security checks (Encryption and Public Access).

**Usage**:

```console
$ sto s3 security all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`: Exit code 1 if risks found (for CI/CD)
* `--json`: Output raw JSON (silences spinner)
* `--csv`: Output CSV (silences spinner)
* `--failures-only`: Only display resources with risks
* `--help`: Show this message and exit.

#### `sto s3 security encryption`

Scan ONLY for default encryption configuration.

**Usage**:

```console
$ sto s3 security encryption [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`: Exit code 1 if risks found
* `--json`: Output JSON
* `--csv`: Output CSV
* `--failures-only`: Show failures only
* `--help`: Show this message and exit.

#### `sto s3 security public-access`

Scan ONLY for public access blocks.

**Usage**:

```console
$ sto s3 security public-access [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--fail-on-risk`: Exit code 1 if risks found
* `--json`: Output JSON
* `--csv`: Output CSV
* `--failures-only`: Show failures only
* `--help`: Show this message and exit.

#### `sto s3 security acls`

Scan ONLY for Legacy ACL usage and Log Delivery compliance.

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
* `--help`: Show this message and exit.
