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

from PySide import QtGui, QtCore, QtUiTools
from PySide.QtCore import Qt

import math

class QSpeedometer(QtGui.QLabel):
    painted = QtCore.Signal()    
    def __init__(self, parent=None):
        super(QSpeedometer, self).__init__(parent)        
        #self.setPixmap('speedometer.png')
        self.setPixmap(QtGui.QPixmap(':/newPrefix/speedometer3.png'))
        self.setScaledContents(True)
        self.setAlignment(QtCore.Qt.AlignCenter)
        self.rx = 0.0
        self.tx = 0.0
        self.animation_rx = 0.0
        self.animation_tx = 0.0
        
        self.base = QtGui.QPixmap(':/newPrefix/speedometer3_base.png')
        
        self.update_delta = 1.0
        self.animation_delta_deg = 0.0
        self.animation_delta = 0.05
        self.animation_timer = None
        

        
    def paintEvent(self, evt):
        super(QSpeedometer, self).paintEvent(evt)
        self.paintTick()
        self.painted.emit()
    
    def bw_to_deg(self, bw):
        # 180 deg is 1Kbps
        # Every 17 degrees goes up a power of two
        # Except that the first 17 degrees is 5 powers!

        #return 158
        
        if bw < 1.0:
            return 180.0
                       
        log = math.log(bw, 2)
        deg = 0.0
        for i in range(int(log)):
            if i < 5:
                deg += 3.5
            else:
                deg += 17
                
        decimal = log - int(log)
        if log < 5:
            deg += decimal * 3.5
        else:
            deg += decimal * 17
        return 180.0 - deg
    
    def update_animation(self):
        # Are we there already?
        
        
        self.animation_rx += self.animation_delta_deg        
        self.update()

        if int(self.animation_rx - self.rx) == 0:
            return 
        
        # Call again in self.animation_delta time
        if not self.animation_timer is None:
            self.animation_timer.stop()
        self.animation_timer = QtCore.QTimer(self)
        self.animation_timer.setSingleShot(True)
        self.animation_timer.timeout.connect(self.update_animation)
        self.animation_timer.start(1000 * self.animation_delta)
        
    
    def change_speed(self, rx, tx):             
        #print "self.rx = %f, rx = %f, delta = %f" % (self.rx, rx, (rx-self.rx)*self.animation_delta)
        self.animation_delta_deg = (rx - self.animation_rx) * self.animation_delta
        self.rx = rx
        self.tx = tx
        #print 'changing speed to %d' % rx
        self.update_animation()
    
    def paintTick(self):
        # where is the tick placed?
        # Let's guesstimate that we have 180 degrees 
        #origin = QtGui.QPoint(180, 93)
        
        radius = 144.0
        origin = QtCore.QPoint(self.width()/2.0-1 , self.height()-3)
        
        
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
                
        deg = self.bw_to_deg(self.animation_rx)
        #deg = self.bw_to_deg(128)

        #x = origin.x() + (radius * math.cos(deg*(math.pi / 180.0)))
        #y = origin.y() -  (radius * math.sin(deg*(math.pi / 180.0)))
        #dst = QtCore.QPoint(x,y)
        #painter.drawLine(origin, dst)





        painter.save()
        #painter.rotate(180-deg)
        painter.translate(origin.x(), origin.y()-3)
        #painter.translate(origin.x(),origin.y())
        
        poly = QtGui.QPolygonF()
        poly.append(QtCore.QPointF(-8, 0))
        poly.append(QtCore.QPointF(8, 0))
        poly.append(QtCore.QPointF(1, -radius))
        poly.append(QtCore.QPointF(-1, -radius))
        #poly.append(QtCore.QPointF(0, -radius))

        matrix = QtGui.QMatrix()
        matrix.rotate(90-deg)
        poly = matrix.map(poly)
        

        # Option to change color of needle based on position
        #d = 180 - deg
        #painter.setBrush(QtGui.QBrush(QtGui.QColor(255, 255-d,  255-d)))
        
        painter.setBrush(QtGui.QBrush(QtGui.QColor(255, 255, 255)))
        
        painter.drawPolygon(poly)
        
        painter.drawPixmap(-1 * 0.5 * self.base.width(), -self.base.height()+8, self.base)
        
        painter.restore()

#        painter.setClipping(True)
                #        painter.clipRegion()
#        bg = QtGui.QPixmap(':/newPrefix/speedometer3.png')
#        painter.setClipRect(QtCore.QRect(0,0,bg.width(), bg.height()-50))


        painter.end()


