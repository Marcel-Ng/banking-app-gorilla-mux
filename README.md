# Official docker documentation for the postgress is here:
https://hub.docker.com/_/postgres

to check my postgres db run
telnet 5432

# Running the docker image of the postgres
- This command only initializes it.
sudo docker run --name some-postgres -e POSTGRES_PASSWORD=bank-app -p 5432:5432 -d postgres

# To run this application we run
make run

# Running the application so as to seed the database
first run
`make run`
then run the following
`./bin/banking-app-gorilla-mux --seed`
to run the seed


# Environment
export JWT_SECRET=marcel_dev999
JWT_SECRET=marcel_dev999