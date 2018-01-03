#!/usr/bin/env bash

services=(fwd idp rp)
node_bin=$(which nodejs)

for service in ${services[*]}; do
    echo "starting $service"
    screen -dmS "$service" bash -c "cd $service; $node_bin $service.js"
    echo -e "done\\n"
done

exit 0
