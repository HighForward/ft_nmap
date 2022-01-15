#!/bin/sh

ssh-keygen -f "/home/forward/.ssh/known_hosts" -R "127.0.0.1"
ssh root@127.0.0.1
