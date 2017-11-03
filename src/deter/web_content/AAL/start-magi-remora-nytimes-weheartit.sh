#!/bin/bash
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2012 - Raytheon BBN Technologies - All Rights Reserved

# MAGI server/control node
control=client0.magi-remora.SAFER
#
ASSESSMENT_DIR=/proj/SAFER/groups/curveball/assessment-2014

/share/safer/magi_core/scripts/magi_orchestrator.py -c ${control} \
    -f ${ASSESSMENT_DIR}/web_content/AAL/remora-servers.groups.aal  \
    -f ${ASSESSMENT_DIR}/web_content/AAL/web-server-start.aal \
    -o ~/magi-remora-run.log -v 

#
#
# Load some useful packages on the client
# python-lxml is required for the script that deploys the content to the web servers
#
ssh ${control} sudo apt-get -y install python-lxml
ssh ${control} sudo apt-get -y install xterm
ssh ${control} sudo apt-get -y install firefox
ssh ${control} sudo apt-get -y install midori
ssh ${control} sudo apt-get -y install twm
ssh ${control} sudo apt-get -y install tightvncserver
# 
# run these commands on the MAGI Server node: client0 on magi-remora.safer
# 
# Load weheartit on servers01-08
ssh ${control} python ${ASSESSMENT_DIR}/web_content/deploy \
    --clients client0,dp0,dr0,client1,dp1,dr1,client2,dp2,dr2,filter,quilt,dns \
    --servers server01,server02,server03,server04,server05,server06,server07,server08 \
    --basehost weheartit.com \
    --contentdir ${ASSESSMENT_DIR}/web_content/cloned/https/weheartit \
    ${ASSESSMENT_DIR}/web_content/cloned/https/weheartit/weheartit.com/index.html 
#
# Load nytimes on servers10-17
ssh ${control} python ${ASSESSMENT_DIR}/web_content/deploy --keep \
    --clients client0,dp0,dr0,client1,dp1,dr1,client2,dp2,dr2,filter,quilt,dns \
    --servers server10,server11,server12,server13,server14,server15,server16,server17  \
    --basehost www.nytimes.com \
    --contentdir ${ASSESSMENT_DIR}/web_content/cloned/http/nytimes \
    ${ASSESSMENT_DIR}/web_content/cloned/http/nytimes/www.nytimes.com/index.html 
