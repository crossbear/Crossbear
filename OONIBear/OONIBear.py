from twisted.python import usage
from ooni.nettest import NetTestCase
from ooni.pyhunter import PyHunter
from pprint import pprint
import traceback
import ConfigParser

class CbOptions(usage.Options):
    optParameters = [
                     ['config', 'c', './cb.conf', 'The configuration file for the test']]





class CBTester(NetTestCase):
    # TODO: Merge this with the `PHunter` class
    author = "Vedat Levi Alev <alev@in.tum.de>"
    name   = "Crossbear OONI"
    version = "0"

    report = {}
    report['errors'] = []
    usageOptions = CbOptions
    
    # for tracerouting
    requiresRoot = True
    requiredOptions = ['config']
    
    def merge(self,partial_report):
        """
        merges the partial_report with the actual report
        """
        for p in partial_report:
            if p not in CBTester.report:
                self.report[p] = partial_report[p]
            else:
                self.report[p] += partial_report[p]
        
    def __init__(self):
        self.cb_host = self.cb_cert = self.max_hops = self.samples_per_hop = None
        NetTestCase.__init__(self)

    def setUp(self):
        # TODO: Find a smart way of handling corrupt config files
        try:
            cf = open(self.localOptions['config'])
        except IOError,e:
            CBTester.report['errors'].append(e)
            return

        try:
            cp = ConfigParser.ConfigParser()
            cp.readfp(cf)
            self.cb_host = cp.get('Server', 'cb_host')
            self.cb_cert = cp.get('Server', 'cb_cert')
            self.max_hops = int(cp.get('Tracer', 'max_hops'))
            self.samples_per_hop = int(cp.get('Tracer', 'samples_per_hop'))
            self.period = int(cp.get('Tracer', 'period'))
        except Exception, e:
            self.report['errors'].append(e)
            return
    
    def test_cb(self):
        try:
            ph = PyHunter.PyHunter(self.cb_host, self.cb_cert, self.max_hops, self.samples_per_hop, self.period)
            r1 = ph.getHTL()
            self.merge(r1)
            r2 = ph.executeHTL()
            self.merge(r2)
        except Exception, e:
            print e
            traceback.print_exc()
            raise e

            








