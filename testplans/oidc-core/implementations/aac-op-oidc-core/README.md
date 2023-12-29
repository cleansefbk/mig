# AAC oidc-core testplan

The main goal is to create a testplan to check AAC, configured as OP, with oidc core profile.

### Environment

[AAC](https://github.com/scc-digitalhub/AAC) is configured as OP.
As RP, a simple Java project is implemented into relying-party-java folder. To build the "rp-java" image, uncomment the related lines into build_and_run.sh command file.
The environment is run by means of a docker-compose yaml, which starts all the containers.

# Simple Relying Party Java

The project uses Java and Spring Boot.
To change ports and configuration, edit \relying-party-java\src\main\resources\application.yml before building the image.