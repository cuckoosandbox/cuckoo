from distutils.core import setup
import py2exe

class Target:
    def __init__(self, **kw):
        self.__dict__.update(kw)
        # for the versioninfo resources
        self.version = "0.5.0"
        self.company_name = "No Company"
        self.copyright = "no copyright"
        self.name = "py2exe sample files"
        
myservice = Target(
    description = "aaaa",
    modules = ['service'],
    cmdline_style='pywin32',
    )
setup(
    #name = 'DemoService',
    #description = 'DemoService description ...',
    #version = '1.00.00',
    #console=['service.py'],
    service = [myservice],
    #zipfile=None,

)
