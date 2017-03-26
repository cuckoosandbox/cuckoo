# Copyright (C) 2012-2015  Diego Torres Milano
# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import sys
import time
import copy
import types
import socket
from lib.api import adb
import xml.parsers.expat
from window import Window
from lib.api.droidbot.common import _nd, _nh, _ns, obtainPxPy, obtainVxVy, obtainVwVh

VIEW_SERVER_HOST = 'localhost'
VIEW_SERVER_PORT = 4939
VERSION_SDK_PROPERTY = 'ro.build.version.sdk'
# some constants for the attributes
VIEW_CLIENT_TOUCH_WORKAROUND_ENABLED = False
ID_PROPERTY = 'mID'
ID_PROPERTY_UI_AUTOMATOR = 'uniqueId'
TEXT_PROPERTY = 'text:mText'
TEXT_PROPERTY_API_10 = 'mText'
TEXT_PROPERTY_UI_AUTOMATOR = 'text'
WS = u"\xfe" # the whitespace replacement char for TEXT_PROPERTY
TAG_PROPERTY = 'getTag()'
LEFT_PROPERTY = 'layout:mLeft'
LEFT_PROPERTY_API_8 = 'mLeft'
TOP_PROPERTY = 'layout:mTop'
TOP_PROPERTY_API_8 = 'mTop'
WIDTH_PROPERTY = 'layout:getWidth()'
WIDTH_PROPERTY_API_8 = 'getWidth()'
HEIGHT_PROPERTY = 'layout:getHeight()'
HEIGHT_PROPERTY_API_8 = 'getHeight()'
GET_VISIBILITY_PROPERTY = 'getVisibility()'
LAYOUT_TOP_MARGIN_PROPERTY = 'layout:layout_topMargin'
IS_FOCUSED_PROPERTY_UI_AUTOMATOR = 'focused'
IS_FOCUSED_PROPERTY = 'focus:isFocused()'

# visibility
VISIBLE = 0x0
INVISIBLE = 0x4
GONE = 0x8

ID_RE = re.compile('id/([^/]*)(/(\d+))?')

class View:
    '''
    View class
    '''

    @staticmethod
    def factory(arg1, version=-1, forceviewserveruse=False, windowId=None):
        '''
        View factory
        @type arg1: ClassType or dict
        @type arg2: View instance or AdbClient
        '''

        if type(arg1) == types.ClassType:
            cls = arg1
            attrs = None
        else:
            cls = None
            attrs = arg1

        view = None

        if attrs and attrs.has_key('class'):
            clazz = attrs['class']
            if clazz == 'android.widget.TextView':
                return TextView(attrs, version, windowId)
            elif clazz == 'android.widget.EditText':
                return EditText(attrs, version, windowId)
            elif clazz == 'android.widget.ListView':
                return ListView(attrs, version, windowId)
            else:
                return View(attrs, version, windowId)
        else:
            return View(attrs, version, windowId)

    @classmethod
    def __copy(cls, view):
        '''
        Copy constructor
        '''

        return cls(view.map, view.version, view.windowId)

    def __init__(self, _map, version=-1, windowId=None):
        '''
        Constructor
        @type _map: map
        @param _map: the map containing the (attribute, value) pairs
        @type device: AdbClient
        @param device: the device containing this View
        @type version: int
        @param version: the Android SDK version number of the platform where this View belongs. If
                        this is C{-1} then the Android SDK version will be obtained in this
                        constructor.
        @type forceviewserveruse: boolean
        @param forceviewserveruse: Force the use of C{ViewServer} even if the conditions were given
                        to use C{UiAutomator}.
        @type uiAutomatorHelper: UiAutomatorHelper
        @:param uiAutomatorHelper: The UiAutomatorHelper if available
        '''
        self.map = _map
        ''' The map that contains the C{attr},C{value} pairs '''
        self.children = []
        ''' The children of this View '''
        self.parent = None
        ''' The parent of this View '''
        self.windows = {}
        self.currentFocus = None
        ''' The current focus '''
        self.windowId = windowId
        ''' The window this view resides '''
        self.build = {}
        ''' Build properties '''
        self.version = version
        ''' API version number '''
        self.uiScrollable = None
        ''' If this is a scrollable View this keeps the L{UiScrollable} object '''
        self.target = False
        ''' Is this a touch target zone '''

        if version != -1:
            self.build[VERSION_SDK_PROPERTY] = version
        else:
            self.build[VERSION_SDK_PROPERTY] = adb.getSDKVersion()

        version = self.build[VERSION_SDK_PROPERTY]
        self.useUiAutomator = True
        ''' Whether to use UIAutomator or ViewServer '''
        self.idProperty = None
        ''' The id property depending on the View attribute format '''
        self.textProperty = None
        ''' The text property depending on the View attribute format '''
        self.tagProperty = None
        ''' The tag property depending on the View attribute format '''
        self.leftProperty = None
        ''' The left property depending on the View attribute format '''
        self.topProperty = None
        ''' The top property depending on the View attribute format '''
        self.widthProperty = None
        ''' The width property depending on the View attribute format '''
        self.heightProperty = None
        ''' The height property depending on the View attribute format '''
        self.isFocusedProperty = None
        ''' The focused property depending on the View attribute format '''

        if version >= 16 and self.useUiAutomator:
            self.idProperty = ID_PROPERTY_UI_AUTOMATOR
            self.textProperty = TEXT_PROPERTY_UI_AUTOMATOR
            self.leftProperty = LEFT_PROPERTY
            self.topProperty = TOP_PROPERTY
            self.widthProperty = WIDTH_PROPERTY
            self.heightProperty = HEIGHT_PROPERTY
            self.isFocusedProperty = IS_FOCUSED_PROPERTY_UI_AUTOMATOR
        elif version > 10 and (version < 16 or self.useUiAutomator):
            self.idProperty = ID_PROPERTY
            self.textProperty = TEXT_PROPERTY
            self.tagProperty = TAG_PROPERTY
            self.leftProperty = LEFT_PROPERTY
            self.topProperty = TOP_PROPERTY
            self.widthProperty = WIDTH_PROPERTY
            self.heightProperty = HEIGHT_PROPERTY
            self.isFocusedProperty = IS_FOCUSED_PROPERTY
        elif version == 10:
            self.idProperty = ID_PROPERTY
            self.textProperty = TEXT_PROPERTY_API_10
            self.tagProperty = TAG_PROPERTY
            self.leftProperty = LEFT_PROPERTY
            self.topProperty = TOP_PROPERTY
            self.widthProperty = WIDTH_PROPERTY
            self.heightProperty = HEIGHT_PROPERTY
            self.isFocusedProperty = IS_FOCUSED_PROPERTY
        elif version >= 7 and version < 10:
            self.idProperty = ID_PROPERTY
            self.textProperty = TEXT_PROPERTY_API_10
            self.tagProperty = TAG_PROPERTY
            self.leftProperty = LEFT_PROPERTY_API_8
            self.topProperty = TOP_PROPERTY_API_8
            self.widthProperty = WIDTH_PROPERTY_API_8
            self.heightProperty = HEIGHT_PROPERTY_API_8
            self.isFocusedProperty = IS_FOCUSED_PROPERTY
        elif version > 0 and version < 7:
            self.idProperty = ID_PROPERTY
            self.textProperty = TEXT_PROPERTY_API_10
            self.tagProperty = TAG_PROPERTY
            self.leftProperty = LEFT_PROPERTY
            self.topProperty = TOP_PROPERTY
            self.widthProperty = WIDTH_PROPERTY
            self.heightProperty = HEIGHT_PROPERTY
            self.isFocusedProperty = IS_FOCUSED_PROPERTY
        elif version == -1:
            self.idProperty = ID_PROPERTY
            self.textProperty = TEXT_PROPERTY
            self.tagProperty = TAG_PROPERTY
            self.leftProperty = LEFT_PROPERTY
            self.topProperty = TOP_PROPERTY
            self.widthProperty = WIDTH_PROPERTY
            self.heightProperty = HEIGHT_PROPERTY
            self.isFocusedProperty = IS_FOCUSED_PROPERTY
        else:
            self.idProperty = ID_PROPERTY
            self.textProperty = TEXT_PROPERTY
            self.tagProperty = TAG_PROPERTY
            self.leftProperty = LEFT_PROPERTY
            self.topProperty = TOP_PROPERTY
            self.widthProperty = WIDTH_PROPERTY
            self.heightProperty = HEIGHT_PROPERTY
            self.isFocusedProperty = IS_FOCUSED_PROPERTY

        try:
            if self.isScrollable():
                self.uiScrollable = UiScrollable(self)
        except AttributeError:
            pass

    def __getitem__(self, key):
        return self.map[key]

    def __getattr__(self, name):
        # NOTE:
        # I should try to see if 'name' is a defined method
        # but it seems that if I call locals() here an infinite loop is entered

        if self.map.has_key(name):
            r = self.map[name]
        elif self.map.has_key(name + '()'):
            # the method names are stored in the map with their trailing '()'
            r = self.map[name + '()']
        elif name.count("_") > 0:
            mangledList = self.allPossibleNamesWithColon(name)
            mangledName = self.intersection(mangledList, self.map.keys())
            if len(mangledName) > 0 and self.map.has_key(mangledName[0]):
                r = self.map[mangledName[0]]
            else:
                # Default behavior
                raise AttributeError, name
        elif name.startswith('is'):
            # try removing 'is' prefix
            suffix = name[2:].lower()
            if self.map.has_key(suffix):
                r = self.map[suffix]
            else:
                # Default behavior
                raise AttributeError, name
        elif name.startswith('get'):
            # try removing 'get' prefix
            suffix = name[3:].lower()
            if self.map.has_key(suffix):
                r = self.map[suffix]
            else:
                # Default behavior
                raise AttributeError, name
        elif name == 'getResourceId':
            if self.map.has_key('resource-id'):
                r = self.map['resource-id']
            else:
                # Default behavior
                raise AttributeError, name
        else:
            # Default behavior
            raise AttributeError, name


        if r == 'true':
            r = True
        elif r == 'false':
            r = False

        # this should not cached in some way
        def innerMethod():
            return r

        innerMethod.__name__ = name

        # this should work, but then there's problems with the arguments of innerMethod
        # even if innerMethod(self) is added
        #setattr(View, innerMethod.__name__, innerMethod)
        #setattr(self, innerMethod.__name__, innerMethod)

        return innerMethod


    def getClass(self):
        '''
        Gets the L{View} class
        @return:  the L{View} class or C{None} if not defined
        '''

        try:
            return self.map['class']
        except:
            return None

    def getId(self):
        '''
        Gets the L{View} Id
        @return: the L{View} C{Id} or C{None} if not defined
        @see: L{getUniqueId()}
        '''

        try:
            return self.map['resource-id']
        except:
            pass

        try:
            return self.map[self.idProperty]
        except:
            return None

    def getContentDescription(self):
        '''
        Gets the content description.
        '''

        try:
            return self.map['content-desc']
        except:
            return None

    def getTag(self):
        '''
        Gets the tag.
        '''

        try:
            return self.map[self.tagProperty]
        except:
            return None

    def getParent(self):
        '''
        Gets the parent.
        '''

        return self.parent

    def getChildren(self):
        '''
        Gets the children of this L{View}.
        '''

        return self.children

    def getText(self):
        '''
        Gets the text attribute.
        @return: the text attribute or C{None} if not defined
        '''

        try:
            return self.map[self.textProperty]
        except Exception:
            return None

    def getHeight(self):
        '''
        Gets the height.
        '''

        return self.map['bounds'][1][1] - self.map['bounds'][0][1]

    def getWidth(self):
        '''
        Gets the width.
        '''

        return self.map['bounds'][1][0] - self.map['bounds'][0][0]

    def getUniqueId(self):
        '''
        Gets the unique Id of this View.
        @see: L{ViewClient.__splitAttrs()} for a discussion on B{Unique Ids}
        '''

        try:
            return self.map['uniqueId']
        except:
            return None

    def getVisibility(self):
        '''
        Gets the View visibility
        '''

        try:
            if self.map[GET_VISIBILITY_PROPERTY] == 'VISIBLE':
                return VISIBLE
            elif self.map[GET_VISIBILITY_PROPERTY] == 'INVISIBLE':
                return INVISIBLE
            elif self.map[GET_VISIBILITY_PROPERTY] == 'GONE':
                return GONE
            else:
                return -2
        except:
            return -1

    def getX(self):
        '''
        Gets the View X coordinate
        '''

        return self.getXY()[0]

    def __getX(self):
        '''
        Gets the View X coordinate
        '''

        x = self.map['bounds'][0][0]

        return x

    def getY(self):
        '''
        Gets the View Y coordinate
        '''

        return self.getXY()[1]

    def __getY(self):
        '''
        Gets the View Y coordinate
        '''

        y = self.map['bounds'][0][1]

        return y

    def getXY(self, debug=False):
        '''
        Returns the I{screen} coordinates of this C{View}.
        WARNING: Don't call self.getX() or self.getY() inside this method
        or it will enter an infinite loop
        @return: The I{screen} coordinates of this C{View}
        '''

        x = self.__getX()
        y = self.__getY()
        
        return (x, y)

    def getCoords(self):
        '''
        Gets the coords of the View
        @return: A tuple containing the View's coordinates ((L, T), (R, B))
        '''

        (x, y) = self.getXY();
        w = self.getWidth()
        h = self.getHeight()
        return ((x, y), (x+w, y+h))

    def getPositionAndSize(self):
        '''
        Gets the position and size (X,Y, W, H)
        @return: A tuple containing the View's coordinates (X, Y, W, H)
        '''

        (x, y) = self.getXY();
        w = self.getWidth()
        h = self.getHeight()
        return (x, y, w, h)

    def getBounds(self):
        '''
        Gets the View bounds
        '''

        if 'bounds' in self.map:
            return self.map['bounds']
        else:
            return self.getCoords()

    def getCenter(self):
        '''
        Gets the center coords of the View
        @author: U{Dean Morin <https://github.com/deanmorin>}
        '''

        (left, top), (right, bottom) = self.getCoords()
        x = left + (right - left) / 2
        y = top + (bottom - top) / 2
        return (x, y)

    def __obtainStatusBarDimensionsIfVisible(self):
        sbw = 0
        sbh = 0
        for winId in self.windows:
            w = self.windows[winId]
            if w.activity == 'StatusBar':
                if w.wvy == 0 and w.visibility == 0:
                    sbw = w.wvw
                    sbh = w.wvh
                break

        return (sbw, sbh)

    def __obtainVxVy(self, m):
        return obtainVxVy(m)

    def __obtainVwVh(self, m):
        return obtainVwVh(m)

    def __obtainPxPy(self, m):
        return obtainPxPy(m)

    def __dumpWindowsInformation(self, debug=False):
        self.windows = {}
        self.currentFocus = None
        dww = adb.shell('dumpsys window windows')
        lines = dww.splitlines()
        widRE = re.compile('^ *Window #%s Window\{%s (u\d+ )?%s?.*\}:' %
                            (_nd('num'), _nh('winId'), _ns('activity', greedy=True)))
        currentFocusRE = re.compile('^  mCurrentFocus=Window\{%s .*' % _nh('winId'))
        viewVisibilityRE = re.compile(' mViewVisibility=0x%s ' % _nh('visibility'))
        # This is for 4.0.4 API-15
        containingFrameRE = re.compile('^   *mContainingFrame=\[%s,%s\]\[%s,%s\] mParentFrame=\[%s,%s\]\[%s,%s\]' %
                             (_nd('cx'), _nd('cy'), _nd('cw'), _nd('ch'), _nd('px'), _nd('py'), _nd('pw'), _nd('ph')))
        contentFrameRE = re.compile('^   *mContentFrame=\[%s,%s\]\[%s,%s\] mVisibleFrame=\[%s,%s\]\[%s,%s\]' %
                             (_nd('x'), _nd('y'), _nd('w'), _nd('h'), _nd('vx'), _nd('vy'), _nd('vx1'), _nd('vy1')))
        # This is for 4.1 API-16
        framesRE = re.compile('^   *Frames: containing=\[%s,%s\]\[%s,%s\] parent=\[%s,%s\]\[%s,%s\]' %
                               (_nd('cx'), _nd('cy'), _nd('cw'), _nd('ch'), _nd('px'), _nd('py'), _nd('pw'), _nd('ph')))
        contentRE = re.compile('^     *content=\[%s,%s\]\[%s,%s\] visible=\[%s,%s\]\[%s,%s\]' %
                               (_nd('x'), _nd('y'), _nd('w'), _nd('h'), _nd('vx'), _nd('vy'), _nd('vx1'), _nd('vy1')))
        policyVisibilityRE = re.compile('mPolicyVisibility=%s ' % _ns('policyVisibility', greedy=True))

        for l in range(len(lines)):
            m = widRE.search(lines[l])
            if m:
                num = int(m.group('num'))
                winId = m.group('winId')
                activity = m.group('activity')
                wvx = 0
                wvy = 0
                wvw = 0
                wvh = 0
                px = 0
                py = 0
                visibility = -1
                policyVisibility = 0x0

                for l2 in range(l+1, len(lines)):
                    m = widRE.search(lines[l2])
                    if m:
                        l += (l2-1)
                        break
                    m = viewVisibilityRE.search(lines[l2])
                    if m:
                        visibility = int(m.group('visibility'))
                    if self.build[VERSION_SDK_PROPERTY] >= 17:
                        m = framesRE.search(lines[l2])
                        if m:
                            px, py = obtainPxPy(m)
                            m = contentRE.search(lines[l2+2])
                            if m:
                                wvx, wvy = obtainVxVy(m)
                                wvw, wvh = obtainVwVh(m)
                    elif self.build[VERSION_SDK_PROPERTY] >= 16:
                        m = framesRE.search(lines[l2])
                        if m:
                            px, py = self.__obtainPxPy(m)
                            m = contentRE.search(lines[l2+1])
                            if m:
                                # FIXME: the information provided by 'dumpsys window windows' in 4.2.1 (API 16)
                                # when there's a system dialog may not be correct and causes the View coordinates
                                # be offset by this amount, see
                                # https://github.com/dtmilano/AndroidViewClient/issues/29
                                wvx, wvy = self.__obtainVxVy(m)
                                wvw, wvh = self.__obtainVwVh(m)
                    elif self.build[VERSION_SDK_PROPERTY] == 15:
                        m = containingFrameRE.search(lines[l2])
                        if m:
                            px, py = self.__obtainPxPy(m)
                            m = contentFrameRE.search(lines[l2+1])
                            if m:
                                wvx, wvy = self.__obtainVxVy(m)
                                wvw, wvh = self.__obtainVwVh(m)
                    elif self.build[VERSION_SDK_PROPERTY] == 10:
                        m = containingFrameRE.search(lines[l2])
                        if m:
                            px, py = self.__obtainPxPy(m)
                            m = contentFrameRE.search(lines[l2+1])
                            if m:
                                wvx, wvy = self.__obtainVxVy(m)
                                wvw, wvh = self.__obtainVwVh(m)
                    else:
                        warnings.warn("Unsupported Android version %d" % self.build[VERSION_SDK_PROPERTY])

                    #print >> sys.stderr, "Searching policyVisibility in", lines[l2]
                    m = policyVisibilityRE.search(lines[l2])
                    if m:
                        policyVisibility = 0x0 if m.group('policyVisibility') == 'true' else 0x8

                self.windows[winId] = Window(num, winId, activity, wvx, wvy, wvw, wvh, px, py, visibility + policyVisibility)
            else:
                m = currentFocusRE.search(lines[l])
                if m:
                    self.currentFocus = m.group('winId')

        if  self.windowId and self.windowId in self.windows and self.windows[self.windowId].visibility == 0:
            w = self.windows[self.windowId]
            return (w.wvx, w.wvy)
        elif self.currentFocus in self.windows and self.windows[self.currentFocus].visibility == 0:
            w = self.windows[self.currentFocus]
            return (w.wvx, w.wvy)
        else:
            return (0,0)

    def touch(self, eventType = adb.DOWN_AND_UP, deltaX=0, deltaY=0):
        '''
        Touches the center of this C{View}. The touch can be displaced from the center by
        using C{deltaX} and C{deltaY} values.
        @param eventType: The event type
        @type eventType: L{adbclient.DOWN}, L{adbclient.UP} or L{adbclient.DOWN_AND_UP}
        @param deltaX: Displacement from center (X axis)
        @type deltaX: int
        @param deltaY: Displacement from center (Y axis)
        @type deltaY: int
        '''

        (x, y) = self.getCenter()
        if deltaX:
            x += deltaX
        if deltaY:
            y += deltaY
        if VIEW_CLIENT_TOUCH_WORKAROUND_ENABLED and eventType == adb.DOWN_AND_UP:
            adb.touch(x, y, eventType=adb.DOWN)
            time.sleep(50/1000.0)
            adb.touch(x+10, y+10, eventType=adb.UP)
        else:
            adb.touch(x, y, eventType=eventType)

    def escapeSelectorChars(self, selector):
        return selector.replace('@', '\\@').replace(',', '\\,')

    def obtainSelectorForView(self):
        selector = ''
        if self.getContentDescription():
            selector += 'desc@' + self.escapeSelectorChars(self.getContentDescription())
        if self.getText():
            if selector:
                selector += ','
            selector += 'text@' + self.escapeSelectorChars(self.getText())
        if self.getId():
            if selector:
                selector += ','
            selector += 'res@' + self.escapeSelectorChars(self.getId())
        return selector

    def longTouch(self, duration=2000):
        '''
        Long touches this C{View}
        @param duration: duration in ms
        '''

        (x, y) = self.getCenter()
        # FIXME: get orientation
        adb.longTouch(x, y, duration, orientation=-1)

    def allPossibleNamesWithColon(self, name):
        l = []
        for _ in range(name.count("_")):
            name = name.replace("_", ":", 1)
            l.append(name)
        return l

    def intersection(self, l1, l2):
        return list(set(l1) & set(l2))

    def containsPoint(self, (x, y)):
        (X, Y, W, H) = self.getPositionAndSize()
        return (((x >= X) and (x <= (X+W)) and ((y >= Y) and (y <= (Y+H)))))

    def add(self, child):
        '''
        Adds a child
        @type child: View
        @param child: The child to add
        '''
        child.parent = self
        self.children.append(child)

    def isClickable(self):
        return self.__getattr__('isClickable')()


    def isFocused(self):
        '''
        Gets the focused value
        @return: the focused value. If the property cannot be found returns C{False}
        '''

        try:
            return True if self.map[self.isFocusedProperty].lower() == 'true' else False
        except Exception:
            return False

    def variableNameFromId(self):
        _id = self.getId()
        if _id:
            var = _id.replace('.', '_').replace(':', '___').replace('/', '_')
        else:
            _id = self.getUniqueId()
            m = ID_RE.match(_id)
            if m:
                var = m.group(1)
                if m.group(3):
                    var += m.group(3)
                if re.match('^\d', var):
                    var = 'id_' + var
        return var

    def setTarget(self, target):
        self.target = target

    def isTarget(self):
        return self.target

    def __smallStr__(self):
        __str = unicode("View[", 'utf-8', 'replace')
        if "class" in self.map:
            __str += " class=" + self.map['class']
        __str += " id=%s" % self.getId()
        __str += " ]   parent="
        if self.parent and "class" in self.parent.map:
            __str += "%s" % self.parent.map["class"]
        else:
            __str += "None"

        return __str

    def __tinyStr__(self):
        __str = unicode("View[", 'utf-8', 'replace')
        if "class" in self.map:
            __str += " class=" + re.sub('.*\.', '', self.map['class'])
        __str += " id=%s" % self.getId()
        __str += " ]"

        return __str

    def __microStr__(self):
        __str = unicode('', 'utf-8', 'replace')
        if "class" in self.map:
            __str += re.sub('.*\.', '', self.map['class'])
        _id = self.getId().replace('id/no_id/', '-')
        __str += _id
        ((L, T), (R, B)) = self.getCoords()
        __str += '@%04d%04d%04d%04d' % (L, T, R, B)
        __str += ''

        return __str


    def __str__(self):
        __str = unicode("View[", 'utf-8', 'replace')
        if "class" in self.map:
            __str += " class=" + self.map["class"].__str__() + " "
        for a in self.map:
            __str += a + "="
            # decode() works only on python's 8-bit strings
            if isinstance(self.map[a], unicode):
                __str += self.map[a]
            else:
                __str += unicode(str(self.map[a]), 'utf-8', errors='replace')
            __str += " "
        __str += "]   parent="
        if self.parent:
            if "class" in self.parent.map:
                __str += "%s" % self.parent.map["class"]
            else:
                __str += self.parent.getId().__str__()
        else:
            __str += "None"

        return __str


class TextView(View):
    '''
    TextView class.
    '''

    pass

class ListView(View):
    '''
    ListView class.
    '''

    pass

class EditText(TextView):
    '''
    EditText class.
    '''

    def type(self, text, alreadyTouched=False):
        if not text:
            return
        if not alreadyTouched:
            self.touch()
        time.sleep(0.5)
        adb.type(text)
        time.sleep(0.5)

    def setText(self, text):
        """
        This function makes sure that any previously entered text is deleted before
        setting the value of the field.
        """
        if self.text() == text:
            return
        self.touch()
        guardrail = 0
        maxSize = len(self.text()) + 1
        while maxSize > guardrail:
            guardrail += 1
            adb.press('KEYCODE_DEL', adb.DOWN_AND_UP)
            adb.press('KEYCODE_FORWARD_DEL', adb.DOWN_AND_UP)
        self.type(text, alreadyTouched=True)

    def backspace(self):
        self.touch()
        time.sleep(1)
        adb.press('KEYCODE_DEL', adb.DOWN_AND_UP)

class UiAutomator2AndroidViewClient():
    '''
    UiAutomator XML to AndroidViewClient
    '''

    def __init__(self, version):
        self.version = version
        self.root = None
        self.nodeStack = []
        self.parent = None
        self.views = []
        self.idCount = 1

    def StartElement(self, name, attributes):
        '''
        Expat start element event handler
        '''
        if name == 'hierarchy':
            pass
        elif name == 'node':
            # Instantiate an Element object
            attributes['uniqueId'] = 'id/no_id/%d' % self.idCount
            bounds = re.split('[\][,]', attributes['bounds'])
            attributes['bounds'] = ((int(bounds[1]), int(bounds[2])), (int(bounds[4]), int(bounds[5])))
            self.idCount += 1
            child = View.factory(attributes, version = self.version)
            self.views.append(child)
            # Push element onto the stack and make it a child of parent
            if not self.nodeStack:
                self.root = child
            else:
                self.parent = self.nodeStack[-1]
                self.parent.add(child)
            self.nodeStack.append(child)

    def EndElement(self, name):
        '''
        Expat end element event handler
        '''

        if name == 'hierarchy':
            pass
        elif name == 'node':
            self.nodeStack.pop()

    def CharacterData(self, data):
        '''
        Expat character data event handler
        '''

        if data.strip():
            data = data.encode()
            element = self.nodeStack[-1]
            element.cdata += data

    def Parse(self, uiautomatorxml):
        # Create an Expat parser
        parser = xml.parsers.expat.ParserCreate()  # @UndefinedVariable
        # Set the Expat event handlers to our methods
        parser.StartElementHandler = self.StartElement
        parser.EndElementHandler = self.EndElement
        parser.CharacterDataHandler = self.CharacterData
        # Parse the XML File
        try:
            encoded = uiautomatorxml.encode(encoding='utf-8', errors='replace')
            _ = parser.Parse(encoded, True)
        except xml.parsers.expat.ExpatError, ex:  # @UndefinedVariable
            print >>sys.stderr, "ERROR: Offending XML:\n", repr(uiautomatorxml)
            raise RuntimeError(ex)
        return self.root

class UiCollection():
    '''
    Used to enumerate a container's user interface (UI) elements for the purpose of counting, or
    targeting a sub elements by a child's text or description.
    '''

    pass


class UiScrollable(UiCollection):
    '''
    A L{UiCollection} that supports searching for items in scrollable layout elements.

    This class can be used with horizontally or vertically scrollable controls.
    '''

    def __init__(self, view):
        self.vc = None
        self.view = view
        self.vertical = True
        self.bounds = view.getBounds()
        (self.x, self.y, self.w, self.h) = view.getPositionAndSize()
        self.steps = 10
        self.duration = 500
        self.swipeDeadZonePercentage = 0.1
        self.maxSearchSwipes = 10

    def flingBackward(self):
        if self.vertical:
            s = (self.x + self.w/2, self.y + self.h * self.swipeDeadZonePercentage)
            e = (self.x + self.w/2, self.y + self.h - self.h * self.swipeDeadZonePercentage)
        else:
            s = (self.x + self.w * self.swipeDeadZonePercentage, self.y + self.h/2)
            e = (self.x + self.w * (1.0 - self.swipeDeadZonePercentage), self.y + self.h/2)
        self.view.device.drag(s, e, self.duration, self.steps, adb.getOrientation())

    def flingForward(self):
        if self.vertical:
            s = (self.x + self.w/2, (self.y + self.h ) - self.h * self.swipeDeadZonePercentage)
            e = (self.x + self.w/2, self.y + self.h * self.swipeDeadZonePercentage)
        else:
            s = (self.x + self.w * (1.0 - self.swipeDeadZonePercentage), self.y + self.h/2)
            e = (self.x + self.w * self.swipeDeadZonePercentage, self.y + self.h/2)
        adb.drag(s, e, self.duration, self.steps, adb.getOrientation())

    def flingToBeginning(self, maxSwipes=10):
        if self.vertical:
            for _ in range(maxSwipes):
                self.flingBackward()

    def flingToEnd(self, maxSwipes=10):
        if self.vertical:
            for _ in range(maxSwipes):
                self.flingForward()

    def scrollTextIntoView(self, text):
        '''
        Performs a forward scroll action on the scrollable layout element until the text you provided is visible,
        or until swipe attempts have been exhausted. See setMaxSearchSwipes(int)
        '''

        if self.vc is None:
            raise ValueError('vc must be set in order to use this method')
        for n in range(self.maxSearchSwipes):
            # FIXME: now I need to figure out the best way of navigating to the ViewClient asossiated
            # with this UiScrollable.
            # It's using setViewClient() now.
            #v = self.vc.findViewWithText(text, root=self.view)
            v = self.vc.findViewWithText(text)
            if v is not None:
                return v
            self.flingForward()
            #self.vc.sleep(1)
            self.vc.dump(-1)
            # WARNING: after this dump, the value kept in self.view is outdated, it should be refreshed
            # in some way
        return None

    def setAsHorizontalList(self):
        self.vertical = False

    def setAsVerticalList(self):
        self.vertical = True

    def setMaxSearchSwipes(self, maxSwipes):
        self.maxSearchSwipes = maxSwipes

    def setViewClient(self, vc):
        self.vc = vc

class ViewClient:

    def __init__(self):
        pass

    def dump(self, window = -1, sleep = 1):
        if sleep > 0:
            time.sleep(sleep)
        version = adb.getSDKVersion()
        if version >= 23:
            pathname = '/storage/self'
            filename = 'window_dump.xml'
            cmd = 'sh /system/bin/uiautomator dump --compressed %s/%s >/dev/null' % (pathname, filename)
            adb.shell(cmd)
            cmd = 'cat %s/%s' % (pathname, filename)
            received = adb.shell(cmd)
        else:
            if version >= 18:
                adb.shell('sh /system/bin/uiautomator dump --compressed window_dump.xml')
                received = adb.shell('cat window_dump.xml')
            else:
                adb.shell('sh /system/bin/uiautomator dump window_dump.xml')
                received = adb.shell('cat window_dump.xml')

        if received:
            received = unicode(received, encoding = 'utf-8', errors = 'replace')
        if not received:
            raise RuntimeError('ERROR: Empty UiAutomator dump was received')

        self.setViewsFromUiAutomatorDump(received)

        return self.views

    def setViewsFromUiAutomatorDump(self, received):
        self.views = []
        self.__parseTreeFromUiAutomatorDump(received)

    def __parseTreeFromUiAutomatorDump(self, receivedXml):
        version = adb.getSDKVersion()
        parser = UiAutomator2AndroidViewClient(version)
        try:
            start_xml_index = receivedXml.index("<")
            end_xml_index = receivedXml.rindex(">")
        except ValueError:
            raise ValueError("received does not contain valid XML: " + receivedXml)

        self.root = parser.Parse(receivedXml[start_xml_index:end_xml_index+1])
        self.views = parser.views
        self.viewsById = {}
        for v in self.views:
            self.viewsById[v.getUniqueId()] = v
        self.__updateNavButtons()

    def __updateNavButtons(self):
        """
        Updates the navigation buttons that might be on the device screen.
        """

        navButtons = None
        for v in self.views:
            if v.getId() == 'com.android.systemui:id/nav_buttons':
                navButtons = v
                break
        if navButtons:
            self.navBack = self.findViewById('com.android.systemui:id/back', navButtons)
            self.navHome = self.findViewById('com.android.systemui:id/home', navButtons)
            self.navRecentApps = self.findViewById('com.android.systemui:id/recent_apps', navButtons)
        else:
            self.navBack = None
            self.navHome = None
            self.navRecentApps = None

    def findViewById(self, viewId, root="ROOT", viewFilter=None):
        '''
        Finds the View with the specified viewId.

        @type viewId: str
        @param viewId: the ID of the view to find
        @type root: str
        @type root: View
        @param root: the root node of the tree where the View will be searched
        @type: viewFilter: function
        @param viewFilter: a function that will be invoked providing the candidate View as a parameter
                           and depending on the return value (C{True} or C{False}) the View will be
                           selected and returned as the result of C{findViewById()} or ignored.
                           This can be C{None} and no extra filtering is applied.

        @return: the C{View} found or C{None}
        '''

        if not root:
            return None

        if type(root) == types.StringType and root == "ROOT":
            return self.findViewById(viewId, self.root, viewFilter)

        if root.getId() == viewId:
            if viewFilter:
                if viewFilter(root):
                    return root
            else:
                return root

        if re.match('^id/no_id', viewId) or re.match('^id/.+/.+', viewId):
            if root.getUniqueId() == viewId:
                if viewFilter:
                    if viewFilter(root):
                        return root;
                else:
                    return root


        for ch in root.children:
            foundView = self.findViewById(viewId, ch, viewFilter)
            if foundView:
                if viewFilter:
                    if viewFilter(foundView):
                        return foundView
                else:
                    return foundView