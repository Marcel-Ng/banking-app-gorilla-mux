# Official docker documentation for the postgress is here:
https://hub.docker.com/_/postgres

to check my postgres db run
telnet 5432

sudo docker run --name some-postgres -e POSTGRES_PASSWORD=bank-app -p 5432:5432 -d postgres