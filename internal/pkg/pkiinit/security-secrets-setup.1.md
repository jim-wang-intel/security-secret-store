% security-secrets-setup(1) Version 1.0 | PKI initialization for EdgeX Foundry secret management subsystem

NAME
====

**security-secrets-setup** — Creates an on-device public-key infrastructure (PKI) to secure microservice secret management

SYNOPSIS
========

| **security-secrets-setup** \[**-workdir** _work-dir_] \[**-deploydir** _deploy-dir_] \[**-cachedir** _cache-dir_] **-generate**|**-cache**|**-import**|**-config** params.json
| **security-secrets-setup** \[**-h**|**--help**]

DESCRIPTION
===========

The Vault secret management component of EdgeX Foundry requires TLS encryption of secrets over the wire via a pre-created PKI.  security-secrets-setup is responsible for creating a certificate authority and any needed TLS leaf certificates in order to secure the EdgeX security services.  security-secrets-setup supports several modes of operation as defined in the OPTIONS section.

As the PKI is security-sensitive, this tool takes a number of precautions to safeguard the PKI:
* The PKI can be deployed to transient storage to address potential attacks to the PKI at-rest.
* The PKI is deployed such that each service has its own assets folder, which is amenable to security controls imposed by container runtimes such as mandatory access controls or file system namespaces.
* The CA private key is shred (securely erased) prior to caching or deployment to block issuance of new CA descendants (this is most relevant in caching mode).

OPTIONS
=====

Modes of operation
-----
-config *params.json*

:   Legacy option from prior version of security-secrets-setup. Deploys PKI using existing behavior in Edinburgh release.

-generate

:   Causes a PKI to be generated afresh every time and deployed. Typically, this will be whenever the framework is started.

-cache

:   Causes a PKI to be generated exactly once and then copied to a designated cache location for future use.  The PKI is then deployed from the cached location.

-import

:   This option is similar to `-cache` in that it deploys a PKI from _cachedir_ to _deploydir_, but it forces an error if _cachedir_ is empty instead of triggering PKI generation.  This enables usage models for deploying a pre-populated PKI such as a Kong certificate signed by an external certificate authority or TLS keys signed by an offline enterprise certificate authority.

Optional switches
-----
-h, --help

:   Prints brief usage information.

-workdir

:   A work area (preferably on a ramdisk) to place working files during certificate generation.  If not supplied, temporary files will be generated to a subdirectory (`/edgex/security-secrets-setup`) of `$XDG_RUNTIME_DIR`, or  underneath `/tmp` if `$XDG_RUNTIME_DIR` is undefined.  Not used in legacy (`-config`) mode.

-deploydir

:   Points to the base directory for the final deployment location of the PKI.  If not specified, defaults to `/run/edgex/secrets/pki/` where each `_service-name_.json` processed causes assets to be placed in `/run/edgex/secrets/pki/_service-name_`. Not used in legacy (`-config`) mode.

-cachedir

:   Points to a base directory to hold the cached PKI, identical in structure to that created in _deploydir_.  Defaults to `/etc/edgex/pki` if not specified.  The PKI is deployed from here when the tool is run in `-cache` or `-import` modes. Not used in legacy (`-config`) mode.

FILES
=====

*_deploydir_/\*\**

:   Target deployment folder for the PKI secrets. Populated with subdirectories named after EdgeX services (e.g. `edgex-vault`) and contains typically two files: `server.crt` for a PEM-encoded end-entity TLS certificate and the corresponding private key in `server.key` as well as a sentinel value `.security-secrets-setup.complete`.

*edgex-vault.json*
*edgex-kong.json*

:   Configuration files for certificate parameters.  The basename of this file creates a corresponding directory under _deploydir_.  For example, `edgex-vault.json` would create assets under `/run/edgex/secrets/pki/edgex-vault/`.  This file conforms to the following schema:

```json
{
    "create_new_rootca": "true|false",
    "working_dir": "./config",
    "pki_setup_dir": "pki",
    "dump_config": "true",
    "key_scheme": {
        "dump_keys": "false",
        "rsa": "false",
        "rsa_key_size": "4096",
        "ec": "true",
        "ec_curve": "384"
    },
    "x509_root_ca_parameters": {
        "ca_name": "EdgeXFoundryCA",
        "ca_c": "US",
        "ca_st": "CA",
        "ca_l": "San Francisco",
        "ca_o": "EdgeXFoundry"
    },
    "x509_tls_server_parameters": {
        "tls_host": "edgex-vault|edgex-kong",
        "tls_domain": "local",
        "tls_c": "US",
        "tls_st": "CA",
        "tls_l": "San Francisco",
        "tls_o": "Kong"
    }
}
```

In `-generate` or `-cache` mode the utility hard-codes the names of the configuration file and always processes `edgex-vault.json` first and `edgex-kong.json` second.  (This is done for now in order to meet the October Fuji deadline.)

*configuration.toml*

:   Configuration file for default options, which can be overridden on the command line.  This file conforms to the following schema:

```ini
[SecretsSetup]
WorkDir = "/path/to/temp/files"
DeployDir = "/path/to/deployed/pki"
CacheDir = "/path/to/cached-or-importing/pki"
Command = "-generate | -config files | ..."
```


ENVIRONMENT
===========

**XDG_RUNTIME_DIR**

:  Used as default value for _workdir_ if not otherwise specified.

NOTES
=====

For backward compatible behavior, use the `-config` option.

New behavior: As security-secrets-setup is a helper utility to ensure that a PKI is created on first launch, it is intended that security-secrets-setup is always invoked with the same operation flag, such as `-generate` or `-cache` or `-import`.   Changing from `-cache` to `-generate` will cause the cache to be ignored when deploying a PKI and changing it back will cause a reversion to a stale CA.  Changing from `-cache` to `-import` mode of operation is not noticeable by the tool--the PKI that is in the cache will be the one deployed.  To force regeneration of the PKI cache after the first launch, the PKI cache must be manually cleaned: the easiest way in Docker would be to delete the Docker volume holding the cached PKI.