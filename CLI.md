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

* `s3`: S3 Auditing &amp; Inventory
* `ec2`: EC2 Auditing &amp; Inventory
* `lambda`: Lambda Auditing &amp; Inventory
* `rds`: RDS Auditing &amp; Inventory

## `sto s3`

S3 Auditing &amp; Inventory

**Usage**:

```console
$ sto s3 [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `security`: S3 Security Audits
* `inventory`: S3 Inventory &amp; Cost Analysis

### `sto s3 security`

S3 Security Audits

**Usage**:

```console
$ sto s3 security [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run ALL S3 Security checks
* `encryption`: Scan for Encryption configuration
* `public-access`: Scan for Public Access Block configuration
* `policy`: Scan for Bucket Policy compliance
* `acls`: Scan for Legacy ACL usage and Log Delivery...
* `versioning`: Scan for Versioning and MFA Delete...
* `object-lock`: Scan for Object Lock configuration
* `naming`: Scan for Predictable Bucket Names
* `website`: Scan for Static Website Hosting configuration

#### `sto s3 security all`

Run ALL S3 Security checks

**Usage**:

```console
$ sto s3 security all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security encryption`

Scan for Encryption configuration

**Usage**:

```console
$ sto s3 security encryption [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security public-access`

Scan for Public Access Block configuration

**Usage**:

```console
$ sto s3 security public-access [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security policy`

Scan for Bucket Policy compliance

**Usage**:

```console
$ sto s3 security policy [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security acls`

Scan for Legacy ACL usage and Log Delivery compliance

**Usage**:

```console
$ sto s3 security acls [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security versioning`

Scan for Versioning and MFA Delete configuration

**Usage**:

```console
$ sto s3 security versioning [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security object-lock`

Scan for Object Lock configuration

**Usage**:

```console
$ sto s3 security object-lock [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security naming`

Scan for Predictable Bucket Names

**Usage**:

```console
$ sto s3 security naming [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 security website`

Scan for Static Website Hosting configuration

**Usage**:

```console
$ sto s3 security website [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--failures-only`: Only display resources with risks
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

### `sto s3 inventory`

S3 Inventory &amp; Cost Analysis

**Usage**:

```console
$ sto s3 inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run all scan.
* `scan`: Gather an inventory of S3 Buckets

#### `sto s3 inventory all`

Run all scan.

**Usage**:

```console
$ sto s3 inventory all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto s3 inventory scan`

Gather an inventory of S3 Buckets

**Usage**:

```console
$ sto s3 inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

## `sto ec2`

EC2 Auditing &amp; Inventory

**Usage**:

```console
$ sto ec2 [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: EC2 Inventory &amp; Audit

### `sto ec2 inventory`

EC2 Inventory &amp; Audit

**Usage**:

```console
$ sto ec2 inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run all scan.
* `scan`: Gather a comprehensive inventory of EC2...

#### `sto ec2 inventory all`

Run all scan.

**Usage**:

```console
$ sto ec2 inventory all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan (e.g. us-east-1)
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto ec2 inventory scan`

Gather a comprehensive inventory of EC2 Instances

**Usage**:

```console
$ sto ec2 inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan (e.g. us-east-1)
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

## `sto lambda`

Lambda Auditing &amp; Inventory

**Usage**:

```console
$ sto lambda [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: Lambda Inventory &amp; Audit

### `sto lambda inventory`

Lambda Inventory &amp; Audit

**Usage**:

```console
$ sto lambda inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `scan`: Gather a comprehensive inventory of Lambda...

#### `sto lambda inventory scan`

Gather a comprehensive inventory of Lambda Functions

**Usage**:

```console
$ sto lambda inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

## `sto rds`

RDS Auditing &amp; Inventory

**Usage**:

```console
$ sto rds [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `inventory`: RDS Inventory &amp; Audit
* `reserved`: RDS Reserved Instance Contracts

### `sto rds inventory`

RDS Inventory &amp; Audit

**Usage**:

```console
$ sto rds inventory [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `all`: Run all scan.
* `scan`: Gather a comprehensive inventory of RDS...

#### `sto rds inventory all`

Run all scan.

**Usage**:

```console
$ sto rds inventory all [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan (e.g. us-east-1)
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

#### `sto rds inventory scan`

Gather a comprehensive inventory of RDS Instances

**Usage**:

```console
$ sto rds inventory scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan (e.g. us-east-1)
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.

### `sto rds reserved`

RDS Reserved Instance Contracts

**Usage**:

```console
$ sto rds reserved [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--help`: Show this message and exit.

**Commands**:

* `scan`: Scan for Purchased Reserved Instances...

#### `sto rds reserved scan`

Scan for Purchased Reserved Instances (Active Contracts).

**Usage**:

```console
$ sto rds reserved scan [OPTIONS]
```

**Options**:

* `--verbose / --no-verbose`: [default: no-verbose]
* `--json`: Output raw JSON
* `--csv`: Output CSV
* `--region TEXT`: Specific AWS Region to scan
* `--org-role TEXT`: IAM role to assume for multi-account scan
* `--help`: Show this message and exit.
