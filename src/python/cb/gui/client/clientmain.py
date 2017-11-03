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

import sys
import os
import subprocess

from PySide import QtGui, QtCore, QtUiTools
from cb.gui.client.clientmainui import Ui_ClientMain
    

class ClientGui(QtGui.QDialog):
    closing = QtCore.Signal()
    def __init__(self, parent=None):
        super(ClientGui, self).__init__(parent)

        self.ui  = Ui_ClientMain()
        self.ui.setupUi(self)
        qApp = QtCore.QCoreApplication.instance()
        self.state = 'disabled'

        # Configure the widget
        self.setWindowTitle('Curveball Client')
        
        # Setup event handlers for the widget
        #qbtn.clicked.connect(qApp.quit)
        #qbtn.resize(qbtn.sizeHint())
        self.ui.launch_browser.clicked.connect(self.launch_browser)
        self.ui.launch_email.clicked.connect(self.launch_email)
        self.ui.launch_other.clicked.connect(self.launch_other)
        self.ui.launch_skype.clicked.connect(self.launch_skype)

        self.set_traffic_color('red')
        self.set_launch_state('disabled')
        
        #self.ui.speedometer.stackUnder(self.ui.img_light_2)
        #self.ui.img_light_2.move(210,75)
        
        
        
        # All done, show the dialog
        self.show()
        
        
    def closeEvent(self, event):
        print "Main window closed"
        self.closing.emit()
        return super(ClientGui, self).closeEvent(event)
                
    def launch(self, cmd):
        if os.name == 'posix':
            cmd = "/bin/sh -c 'tsocks %s'" % cmd
            p = subprocess.Popen(cmd, shell=True)

    def tunnel_up(self, args):
        """ Signal handler from CCP """
        print "tunnel up!"
        self.set_traffic_color('green')
        self.set_launch_state('enabled')
        
    def tput_update(self, (tx, rx)):
        """ Signal handler from CCP """
        if not self.state == 'enabled':
            return
        
        self.ui.label_ready.setText("Rx: %.0f Kbps  Tx: %.0f Kbps" % (rx, tx))
        self.ui.speedometer.change_speed(rx,tx)
        
    def launch_browser(self):
        print "Closing firefox first"

	if sys.platform == 'win32':
	    os.system('taskkill -f -im firefox.exe')
	else:
	    os.system('killall firefox')
        print "Launching Firefox"
        self.launch('firefox')
    
    def launch_email(self):
        print "Launching email"

    def launch_skype(self):
        print "Launching skype"
    
    def launch_other(self):
        print "Launching other"


    def set_launch_state(self, state):
        buttons = [self.ui.launch_browser, self.ui.launch_email,
                   self.ui.launch_other, self.ui.launch_skype]
        b = False
        self.state = state
        if state == 'enabled':
            b = True
            
        for button in buttons:
            button.setEnabled(b)
        
    def set_traffic_color(self, color):
        if color == 'red':
            self.ui.label_ready.setText(self.tr('Connecting, please wait...'))
#            self.ui.img_light_2.setPixmap(QtGui.QPixmap(":/newPrefix/traffic-light-red.jpg"))
        elif color == 'green':
            #setPixmap(QPixmap(":/new/prefix1/images/FirefoxCool.png") );             
           self.ui.label_ready.setText(self.tr('Connected!'))
#            self.ui.img_light_2.setPixmap(QtGui.QPixmap(":/newPrefix/traffic-light-green.jpg"))
    
    
def init():
    qApp = QtGui.QApplication([])
    qApp.setApplicationName('Curveball Client')

    import cb.gui.qtreactor

    cb.gui.qtreactor.install()
    
    from twisted.internet import reactor 
    gui = ClientGui()
    

    # If the main dialog closes, shut everything down
    # This wouldn't normally be necessary if we used the regular QT
    # event loop but the twisted reactor calls a different qt event loop
    # which doesn't trigger the quit on last window closed signal
    gui.closing.connect(reactor.stop)

    # make sure stopping twisted event also shuts down QT
    reactor.addSystemEventTrigger('after', 'shutdown', qApp.quit )

    gui.show()       
    #reactor.run()
    #qApp.exec_()

    return gui
    
if __name__ == '__main__':
    gui = init()
    from twisted.internet import reactor 
    reactor.run()
