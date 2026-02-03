#!/usr/bin/env bash
sudo systemctl stop docker
sudo rm -rf /var/lib/docker/*
sudo systemctl start docker
