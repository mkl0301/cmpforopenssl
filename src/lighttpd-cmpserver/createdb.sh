#!/bin/sh
# simple script to create the sqlite database where certificates are stored
# usage: createdb.sh <dbfile>
sqlite3 $1 "create table certs (serial int not null primary key, name varchar not null, cert blob not null);"
