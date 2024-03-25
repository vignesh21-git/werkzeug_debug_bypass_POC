#!/bin/bash
docker rm -f web_werkzueg_python
docker build --tag=web_werkzueg_python .
docker run -p 1337:1337 --rm --name=web_werkzueg_python web_werkzueg_python
