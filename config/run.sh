#!/bin/sh

MOLLY_CONFIG=/home/molly/burp_molly_config.json /usr/lib/jvm/jre1.8.0_111/bin/java -jar -Xmx2048m -Djava.awt.headless=true burpsuite_pro.jar --user-config-file=/home/molly/burp_user_config.json --config-file=/home/molly/burp_project_config.json
