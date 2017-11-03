#!/bin/bash
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2012 - Raytheon BBN Technologies - All Rights Reserved

# MAGI server/control node
control=client.cb-min-webclone20.SAFER
#
ASSESSMENT_DIR=/proj/SAFER/groups/curveball/assessment-2014

/share/safer/magi_core/scripts/magi_orchestrator.py -c ${control} \
    -f ${ASSESSMENT_DIR}/web_content/AAL/20nodes.groups.aal  \
    -f ${ASSESSMENT_DIR}/web_content/AAL/web-traffic-start.aal \
    -o ~/cnn-nytimes-run.log -v 

#
# run these commands on the MAGI Server node: client on cb-min-webclone20 
#
ssh ${control} sudo apt-get -y install python-lxml
ssh ${control} sudo apt-get -y install xterm
ssh ${control} sudo apt-get -y install firefox
ssh ${control} sudo apt-get -y install midori
ssh ${control} sudo apt-get -y install twm
ssh ${control} sudo apt-get -y install tightvncserver
# 
# Load weheartit on servers01-08
ssh ${control} python ${ASSESSMENT_DIR}/web_content/deploy \
    --clients client,dp,dr,filter,quilt,webclient,webgw \
    --servers server01,server02,server03,server04,server05,server06,server07,server08 \
    --basehost weheartit.com \
    --contentdir ${ASSESSMENT_DIR}/web_content/cloned/https/weheartit \
    ${ASSESSMENT_DIR}/web_content/cloned/https/weheartit/weheartit.com/index.html 
#
# Load nytimes on servers10-17
ssh ${control} python ${ASSESSMENT_DIR}/web_content/deploy --keep --clients client,dp,dr,filter,quilt,webclient,webgw \
    --servers server10,server11,server12,server13,server14,server15,server16,server17  \
    --basehost www.nytimes.com \
    --contentdir ${ASSESSMENT_DIR}/web_content/cloned/http/nytimes \
    ${ASSESSMENT_DIR}/web_content/cloned/http/nytimes/www.nytimes.com/index.html 
