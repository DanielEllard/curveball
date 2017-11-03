#!/usr/bin/env python

import unittest2
import os
import logging
import time
import sys
import yaml

sys.path.append(os.path.join(__file__, '../../python'))

from magi.messaging.api import MAGIMessage
from magi.tests.util import AgentUnitTest
import magi.util.execl

import apache  # the module under test

class ApacheTest(AgentUnitTest):
	""" Testing of apache server """

	AGENT = apache
	test_IDL = AgentUnitTest.idltest(os.path.join(os.path.dirname(__file__), "apache.idl"))

	def test_apache(self):
		""" Test load, start and stop of apache """
		start = { 'version': 1.0, 'method': 'startServer' }
		stop = { 'version': 1.0, 'method':'stopServer' }
		config = {
			'version': 1.0,
			'method':'setConfig',
			'args': { 'StartServers': 2 }
		}

		magi.util.execl.execDebug = True  # Don't run, just log

		self.fixture.inject(MAGIMessage(src='guinode', data=yaml.safe_dump(config)))
		self.fixture.inject(MAGIMessage(src='guinode', data=yaml.safe_dump(start)))
		self.fixture.inject(MAGIMessage(src='guinode', data=yaml.safe_dump(stop)))
		time.sleep(0.5)
		self.assertEquals(magi.util.execl.execCalls[0], "apache2ctl -k start")
		self.assertEquals(magi.util.execl.execCalls[1], "apache2ctl -k stop")
		# TODO: check config file

if __name__ == '__main__':
	AgentUnitTest.agentMain()

