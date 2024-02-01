# Test AAC as Relying Party

Starting from [spid-cie-oidc-django](https://github.com/italia/spid-cie-oidc-django)  implementation, we added
- i-mig-t, which contains Burp Suite, a proxy able to intercept HTTP messages between the containers. 
- Identity manager [AAC](https://github.com/scc-digitalhub/AAC) configured as Relying Party
 

## Quickstart

Before starting configure a proper DNS resolution for the following domain names. In GNU/Linux we can configure it by inserting in `/etc/hosts` the following string:

```bash
127.0.0.1   localhost  aac-provider.org trust-anchor.org cie-provider.org
```

To execute the infrastructure follow the steps depending on your OS:

### linux

<details>
The infrastructure can be executed on linux using the two `.sh` files provided:

- `build_and_run.sh` This file is useful when changes to the files are made or it is the first time that the infrastructure is run. It clones the [original repository](https://github.com/italia/spid-cie-oidc-django), applies some changes to the configuration, builds the proxy container (file [burpsuite_container/Dockerfile](burpsuite_container/Dockerfile)) and runs all together.
- `run.sh` It runs the infrastructure directly, without cloning the repo or applying changes.
- `stop.sh` It stops the infrastructure.


</details>

## AAC configuration
AAC configuration is loaded at startup using `\testplans\spid-cie-oidc\implementations\aac-rp-federation\config\aac\bootstrap.yaml` file.

## Using MIG-T

When the infrastructure is running, [MIG-T](https://github.com/stfbk/mig-t) can be used. It requires two inputs:

- **Session:**
- **Machine-Readable (MR) Tests:**

refer to [this readme](/tools/i-mig-t/readme.md#using-mig-t) for details.

### Sessions

Test normally use the session `s_CIE` which provides a basic login and logout flow. Nonetheless, other sessions can be found:

- **s1-logout:** base session without the logout;
- **s1-credentials:** base session without the insertion of the credentials.

In MIG the text of the file corresponding to the defined session must be used.

### MR tests

Only the RP scenario is considered, the tests executed are into folder
`\testplans\spid-cie-oidc\implementations\aac-rp-federation\input\mig-t\tests`

## Known Bugs

When running the infrastructure, it can happen that burp exits with a 0 error code. It will be enough to restart Burp by executing the following command:

```restart_burp.sh```

## Cleaning

After using the infrastructure several times, it is likely that the space occupied by the docker cache is quite huge. It could be useful to run directly `docker system prune` to prune all objects together or, alternatively, to run `docker builder prune` (which will free the docker cache that occupies most of the space) and perform single objects [pruning](https://docs.docker.com/config/pruning/) if necessary.
