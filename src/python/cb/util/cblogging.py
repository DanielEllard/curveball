#!/usr/bin/env python
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2014 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

""" The Curveball Logging Setup
    Use names like: 'cb', 'cb.tcphijack', 'cb.dr2dp', etc..
    
    You only need to import this module once in your program,
    but multiple imports won't hurt
    
    The log file rotates each instantiation so you can compare
    the current log file to previous runs.  Currently it only
    saves 1 backup, but this can be changed with the backupCount
    parameter.
"""

import errno
import logging
import logging.handlers
import os
import os.path
import socket
import sys
import cb.util.platform

class CurveballLogger(object):
    """
    Wrapper class to keep the global namespace clean
    """

    LOG_SUFFIX = '.log'

    @staticmethod
    def choose_filename():
        """
        Create a filename for the log file from sys.argv[0].

        Even if sys.argv[0] points to another directory, we always create the
        log in the current working directory.

        Assumes that nobody has clobbered sys.argv[0].
        """

        (_head, tail) = os.path.split(sys.argv[0])

        if not tail:
            # Can this even happen?  If it does, punt.
            tail = 'CurveballLogger'

        (root, _ext) = os.path.splitext(tail)

        return './%s-%s%s' % (root, socket.gethostname(),
                CurveballLogger.LOG_SUFFIX)

    @staticmethod
    def init_logger(filename='', loggername='cb',
            level=logging.WARNING, backup_count=1, want_stream=False):
        """
        Initialize a logger for this process.

        filename - the file to store the default logger.  If a filename
            is not supplied or is '', then a name in the working directory,
            based on the name of the script with .log append, is used
            (Assuming that nobody has clobbered sys.argv[0])

        loggername - the name of the logger.  This should be the prefix
            that all of the other loggers are going to use.  The default
            is 'cb'.

        level - the active logging level

        backup_count - how many previous copies of the log file to keep

        want_stream - if non-False, add a Stream handler in addition to the
            RotatingFile handler.

        """

        if not filename:
            filename = CurveballLogger.choose_filename()

        try:
            if os.environ['SSLDEBUG']:
                level = logging.DEBUG
        except KeyError, e:
            # it's okay if the envar is not set
            pass

        # Set up a specific logger with our desired output level
        logger = logging.getLogger(loggername)
        logger.setLevel(level)

        # TODO - We might want to add the date to the log entries.
        #
        formatter = logging.Formatter(
                '%(asctime)s %(name)s %(module)s:%(lineno)d ' +
                '%(levelname)s: %(message)s')
                #datefmt='%H:%M:%S')


        # Initialize android logging if on an Android platform
        #
        # There doesn't seem to be a better way to test whether
        # we're on Android than trying to import the android module
        # and if this raises an exception, assume we're not.
        #
        if cb.util.platform.PLATFORM == 'android':
            import androidhandler

            logging.handlers.AndroidHandler = androidhandler.AndroidHandler

            handler = logging.handlers.AndroidHandler()

	else:
	    # Add the log message handler to the logger
            try:
                handler = logging.handlers.RotatingFileHandler(
                        filename, backupCount=backup_count)
            except IOError, exc:
                if exc.errno == errno.EACCES:
                    print 'ERROR: insufficient privileges to init logfile'
                    print 'ERROR: sudo may be necessary'
                    sys.exit(1)
            except BaseException, exc:
                print 'ERROR: cannot initialize log file: %s' % str(exc)
                sys.exit(1)

	    # Start a fresh log file each run
	    handler.doRollover()

            # try to leave the file permissions on the log file such
            # that the next process can modify them, even if it's not
            # root.  This is dangerous.
            #
            if cb.util.platform.PLATFORM in ['android', 'darwin', 'linux2']:
                try:
                    os.chmod(filename, 0666)
                except:
                    pass

	handler.setFormatter(formatter)

	logger.addHandler(handler)
	

        # After we create the logger, I think we need need to stash a reference
        # to it somewhere so we don't lose it.  It might hang around in a
        # private namespace whether we do this or not, but this isn't too gross
        # because this puts it in a class-scope variable, so the global
        # namespace is untouched.
        #
        CurveballLogger.logger = logger

        # If you want a stream handler...
        #
        if want_stream:
            add_stderr()

def add_stderr():

    serr = logging.StreamHandler()

    formatter = logging.Formatter(
            '%(asctime)s %(name)s %(module)s:%(lineno)d ' +
            '%(levelname)s: %(message)s')
    serr.setFormatter(formatter)

    CurveballLogger.logger.addHandler(serr)

CurveballLogger.init_logger()

if __name__ == '__main__':
    # This is for eyeball use only
    #
    print 'I would use logger file (%s)' % (CurveballLogger.choose_filename(),)

