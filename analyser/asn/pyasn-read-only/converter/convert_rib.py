#!/usr/bin/python

# MRT RIB log import  [to convert to a text IP-ASN lookup table]
# Author hadi asghari (hd dot asghari at gmail) of TUDelft.nl
# v1.0 on 25-nov-2009, v1.2 on 02-dec-2009  


# file to use per day should be of these series:
# http://archive.routeviews.org/bgpdata/2009.11/RIBS/rib.20091125.0600.bz2


import bz2
import time
import sys

import mrt_ex   # our own module, also included
#reload(mrt_ex) # for debugging


print 'MRT RIB log importer v1.2.'


#sys.argv = ['x', 'c:/users/hadi/downloads/rviews/20091202 rib.bz2', 'd:/asndat_20091202.dns_rib'] # for debugging

if len(sys.argv) != 3:
    print '\nUsage:  convert_rib.py   <ribmrtdump_file.bz2>   <ipasndat_file>'
    print '\nDownload RIBs from: http://archive.routeviews.org/bgpdata/2009.xx/RIBS/xxx.bz2'		
    sys.exit()


dump_file = sys.argv[1] 
out_file  = sys.argv[2] 
st = time.time()


f = bz2.BZ2File(dump_file, 'rb')

dat = {}
curly = {}
as32 = {}
excl = {}


# get rib dump type
s = f.read(mrt_ex.MRTHeader2.HDR_LEN)
mrt_h = mrt_ex.MRTHeader2(s)
tdv = 2 if mrt_h.type == mrt_ex.TABLE_DUMP_V2 else 1 if mrt_h.type == mrt_ex.TABLE_DUMP_V1 else -1
if tdv == -1:
    raise Exception('unknown table_dump type')

print 'Processing %s\nRIB TableDumpV%d' % (f.name, tdv)
f.seek(0)

nn = 0
seq_no = -1


while True:
    s = f.read(mrt_ex.MRTHeader2.HDR_LEN)
    if len(s) == 0:
        break    
    assert len(s) == mrt_ex.MRTHeader2.HDR_LEN
    
    mrt_h = mrt_ex.MRTHeader2(s)
    s = f.read(mrt_h.len)
    assert len(s) == mrt_h.len
        
    nn += 1

    if tdv == 2:
        # TABLE_DUMP V2 importer
        if nn % 5000 == 1: 
            print '.',
            sys.stdout.flush()
            
        assert mrt_h.type == mrt_ex.TABLE_DUMP_V2        
        if mrt_h.subtype == mrt_ex.TableDumpV2.PEER_INDEX_TABLE:
            continue 
        assert mrt_h.subtype == mrt_ex.TableDumpV2.RIB_IPV4_UNICAST

        td = mrt_ex.TableDumpV2(s)
        k = (td.cidr, td.bitmask)
		
        #assert (k not in curly) and (k not in as32) and (k not in dat)

        # the following code detects asn flips; however, since we understood
        # that routeviews always takes the first match, there is no need for it
        #owner = None    
        #for e in td.entries:
        #    as_path = e.as_path()
        #    if owner is None:
        #        owner = as_path.owning_asn()
        #    elif owner != as_path.owning_asn():
        #        flipped.add(k) 
        #        break

        owner = td.entries[0].as_path().owning_asn()            
        assert owner is not None
    #
    
    elif tdv == 1:        
        # TABLE_DUMP-v1 importer code
        if nn % 100000 == 1: 
            print '.',
            sys.stdout.flush()
        
        assert mrt_h.type == mrt_ex.TABLE_DUMP_V1
        assert mrt_h.subtype == 1 # 'unexpected ip family: %d'

        td = mrt_ex.TableDumpV1(s)       
        k = (td.cidr, td.bitmask)        
        owner = None
        
        if (k not in curly) and (k not in as32) and (k not in dat):
            # only interested in getting the first match, that's why we check          
            owner = td.as_path().owning_asn()
            assert owner is not None
    #    


    if owner is None:  pass  
    elif '{' in owner: curly[k]= owner
    elif '.' in owner: as32[k] = owner
    elif '!' in owner: excl[k] = owner
    else:              dat[k]  = int(owner)

    #print '#%d\t%s\t/%d\t-> asn: %s' % (td.seq, k[0], k[1], owner)

    seq_no += 1
    if seq_no == 65536 and tdv == 1: seq_no = 0
    assert td.seq == seq_no
	
#

f.close()

try: del dat['0.0.0.0', 0]  # remove default route
except: pass

print '\nRecords processed: %d in %.1fs' % (nn, time.time()-st)



# CREATE OUTPUT FILE
fw = open(out_file, 'w')

fw.write('; IP-ASN-DAT file\n; Original file : %s\n' % dump_file)
fw.write('; Converted on  : %s\n; CIDRs         : %s\n; \n' % (time.asctime(), len(dat)) )

for cidr_mask,asn in sorted(dat.iteritems()):
    s = '%s/%d\t%d\n' % (cidr_mask[0],cidr_mask[1],asn)
    fw.write(s)
fw.close()


print 'IPASNDAT file saved (%d CIDRs, else:%d/%d/%d)' % (len(dat), len(curly), len(as32), len(excl))
