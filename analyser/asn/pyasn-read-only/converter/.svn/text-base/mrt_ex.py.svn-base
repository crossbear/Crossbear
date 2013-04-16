# extension module to the "dpkt" library to parse TableDumpV2 MRT/RIB files
# use: parsing routeviews files and creating an IP to ASN list
# author hadi a
# note: parts of this code are copied/based on the dpkt project
# date 24.11.2009 v 1.1    , 02-12-2009 v1.2

# note: this module might be speeded up by replacing some struct.unpacks with ord()


import struct

TABLE_DUMP_V1 = 12
TABLE_DUMP_V2 = 13

AS32_SIZE = pow(2,16)


class MRTHeader2:

    HDR_LEN = 12
    
    def __init__(self, buf):
        self.ts, self.type, self.subtype, self.len = struct.unpack('>IHHI', buf[0:12])
        self.data = buf[12:]

    def __str__(self):
        return 'mrt_{ts:%d,type:%d,subtype:%d,len:%d}'% (self.ts, self.type, self.subtype, self.len)

    def __repr__(self):
        return str(self)



class TableDumpV1:

    def __init__(self, buf):
        self.view, self.seq, prefix, self.bitmask, self.status, self.originate_ts, self.peer_ip, self.peer_as, self.attr_len\
                   = struct.unpack('>HHIBBIIHH', buf[:22])

        assert self.view == 0 # not necessary but in our data is so
        assert self.status == 1

        self.cidr = '%d.%d.%d.%d' % (prefix>>24&0xff, prefix>>16&0xff, prefix>>8&0xff, prefix&0xff)
        self.data = buf[22:]

        self.attrs = None


    def as_path(self):
        self.parse_attrs()
        
        as_path = None
        for x in self.attrs:
            if x.type == Attribute.AS_PATH:
                assert as_path is None # "two aspaths"
                as_path = x.as_path

        assert as_path is not None # no as path?
        return as_path

    def parse_attrs(self):
        if self.attrs is not None:
            return
        
        plen = self.attr_len
        l = []
        while plen > 0:
            attr = Attribute(self.data, False)
            self.data = self.data[len(attr):]
            plen -= len(attr)
            l.append(attr)
        #
        assert len(self.data) == 0        
        self.attrs = l
        

    def __str__(self):
        return 'TableDumpV1{seq:%d,cidr:%s,bitmask:%d,attr_len:%d,peer_as:%d,status:%d,originate_ts:%d}' % \
               (self.seq, self.cidr, self.bitmask, self.attr_len, self.peer_as, self.status, self.originate_ts)

    def __repr__(self):
        return str(self)
        


class TableDumpV2:

    # TABLE_DUMP_V2 subtypes used:
    PEER_INDEX_TABLE = 1
    RIB_IPV4_UNICAST = 2

    PARSE_ONLY_FIRST_TDENTRY = True # !!! for speedup, as we only use the path on the first one


    def __init__(self, buf):
        self.seq, self.bitmask = struct.unpack('>IB', buf[0:5])

        octets = (self.bitmask + 7) / 8
        if octets == 0:
            self.cidr = '0.0.0.0'
            px = 5
        elif octets == 1:
            self.cidr = '%d.0.0.0' % ord(buf[5])
            px = 6
        elif octets == 2:
            self.cidr = '%d.%d.0.0' % tuple(map(ord, buf[5:7]))
            px = 7
        elif octets == 3:
            self.cidr = '%d.%d.%d.0' % tuple(map(ord, buf[5:8]))
            px = 8
        else:
            self.cidr = '%d.%d.%d.%d' % tuple(map(ord, buf[5:9]))
            px = 9
        
        self.entry_count = struct.unpack('>H', buf[px:px+2])[0]
        buf = buf[px+2:]

        f_parseattrs = True
        f_parseattrs_2nd = not self.PARSE_ONLY_FIRST_TDENTRY
        
        self.entries = []
        for ix in range(self.entry_count,0,-1):
            et = TDEntry(buf, f_parseattrs)
            self.entries.append(et)
            
            buf = et.raw
            et.raw = None
            f_parseattrs = f_parseattrs_2nd
        #

        assert len(buf) == 0


    def __str__(self):
        return 'TableDumpV2{seq:%d,cidr:%s,bitmask:%d,entry_count:%d}' % (self.seq, self.cidr, self.bitmask, self.entry_count)

    def __repr__(self):
        return str(self)





class TDEntry:
    def __init__(self, buf, f_parseattrs):
        self.peer_index, self.originate_ts, self.attr_len = struct.unpack('>HIH', buf[0:8])
        self.data = buf[8 : 8 + self.attr_len]
        self.raw = buf[8+self.attr_len:]

        plen = self.attr_len
        l = []

        if f_parseattrs:
            while plen > 0:
                attr = Attribute(self.data, True) 
                self.data = self.data[len(attr):]
                plen -= len(attr)
                l.append(attr)

            assert(plen == 0)
        
        self.attrs = l

    def __str__(self):
        return 'TDEntry{peer_index: %d, originate_ts: %d, attr_len: %d}' % (self.peer_index, self.originate_ts, self.attr_len)

    def __repr__(self):
        return str(self)

    def as_path(self):
        as_path = None
        for x in self.attrs:
            if x.type == Attribute.AS_PATH:
                assert as_path is None # "TDEntry.two aspaths"
                as_path = x.as_path

        assert as_path is not None # "TDEntry.no aspaths"
        return as_path


class Attribute:

    # attribute types we use
    AS_PATH				= 2


    def _get_o(self):
        return (self.flags >> 7) & 0x1
    def _set_o(self, o):
        self.flags = (self.flags & ~0x80) | ((o & 0x1) << 7)
    optional = property(_get_o, _set_o)

    def _get_t(self):
        return (self.flags >> 6) & 0x1
    def _set_t(self, t):
        self.flags = (self.flags & ~0x40) | ((t & 0x1) << 6)
    transitive = property(_get_t, _set_t)

    def _get_p(self):
        return (self.flags >> 5) & 0x1
    def _set_p(self, p):
        self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)
    partial = property(_get_p, _set_p)

    def _get_e(self):
        return (self.flags >> 4) & 0x1
    def _set_e(self, e):
        self.flags = (self.flags & ~0x10) | ((e & 0x1) << 4)
    extended_length = property(_get_e, _set_e)


    def __init__(self, buf, is32):
        self.flags, self.type = struct.unpack('>BB', buf[0:2])
        self.data = buf[2:]
    
        if self.extended_length:
            self.len = struct.unpack('>H', self.data[:2])[0]
            self.data = self.data[2:]
        else:
            self.len = struct.unpack('B', self.data[:1])[0]
            self.data = self.data[1:]
            
        self.data = self.data[:self.len]


        if self.type == self.AS_PATH:
                self.as_path = self.ASPath32(self.data, is32)

        # We do not use the rest of the attributes, so I have not configured them for speed
        # stats on usage in TDv2 files(on approx 100.000 thousand):
        #ORIGIN 1=24%  
        #AS_PATH 2=24%
        #NEXT_HOP 3=24%
        #MULTI_EXIT_DISC 4=10%
        #ATOMIC_AGGREGATE 6=1.5%
        #AGGREGATOR 7=2.5%
        #COMMUNITIES 8=14%        

    
    def __len__(self):
        attr_len = 2 if self.extended_length else 1
        return 2 + attr_len + len(self.data)

    def __str__(self):
        if self.extended_length:
            attr_len_str = struct.pack('>H', self.len)
        else:
            attr_len_str = struct.pack('B', self.len)

        return 'Attr2{type:%d,flags:%d,len(data):%d}' % (self.type, self.flags, len(self.data))

    def __repr__(self):
        return str(self)

        

    class ASPath32:

        # AS_Path types we use:
        AS_SET          = 1
        AS_SEQUENCE     = 2

            
        def __init__(self, buf, is32):
            self.segments = []
            self.data = buf
            l = []
            while self.data:
                seg = self.ASPathSegment32(self.data, is32)
                self.data = self.data[len(seg):]
                l.append(seg)
            self.data = self.segments = l

        def __len__(self):
            return sum(map(len, self.data))

        def __str__(self):
        #    return ''.join(map(str, self.data))
            return repr(self)
        

        def __repr__(self):
            return 'ASPath32{segments:%d,path:%s}' % (len(self.segments), str(self.segments))

        def owning_asn(self):
            if len(self.segments) == 1:
                x = int(self.segments[0].path[-1]) 
                if x > AS32_SIZE or x < 0:
                    return '%d.%d' % (x>>16, x&0xffff)  # correct?
                return str(x)

            elif len(self.segments) == 2 and self.segments[0].type==self.AS_SEQUENCE and self.segments[1].type==self.AS_SET:
                x = str(self.segments[1]) #or self.segments[1].path[-1]?
                assert '{' in x
                return x

            else:
                return '!' + str(self.segments)



        class ASPathSegment32:

            # AS_Path types we use:  
            AS_SET          = 1     # shouldn't have to copy these globals in both classes
            AS_SEQUENCE     = 2

            
            def __init__(self, buf, is32):
                self.type, self.len = struct.unpack('>BB', buf[:2])
                self.data = buf[2:]
                self.aslen = 4 if is32 else 2

                #print self.type 
                assert self.type==self.AS_SET or self.type==self.AS_SEQUENCE  or self.type==3  # 3!
                # stats on 100,000: {1: 1196, 2: 3677845}
                
                l = []
                for i in range(self.len):
                    if is32:
                        AS = struct.unpack('>I', self.data[:4])[0]
                        self.data = self.data[4:]
                    else:
                        AS = struct.unpack('>H', self.data[:2])[0]
                        self.data = self.data[2:]                        
                    l.append(AS)
                #    
                self.data = self.path = l
                

            def __len__(self):
                return 2 + self.aslen*len(self.path)

            def __str__(self):
                #assert self.type==self.AS_SET or self.type==self.AS_SEQUENCE                   

                as_str = '' if self.type==self.AS_SEQUENCE else '{' if self.type==self.AS_SET else '<<'
                for AS in self.path:                        
                    as_str += str(AS) + ' '                    
                as_str = as_str.strip()
                as_str += '' if self.type==self.AS_SEQUENCE else '}' if self.type==self.AS_SET else '>>'                    

                return as_str

            def __repr__(self):
                return str(self)


    
