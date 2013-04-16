README file, written on 01-12-2009


Module name: PyASN module 
Version    : 1.2 @27-11-2009   (v1.0 05-11-2009)
Description: Python extension module that returns the autonomous system number
	     for any given IP address 


**** Credits:

Written by Hadi Asghari (hd dot asghari at gmail)  of TUDelft.nl
Based on code design by Dr. Christopher Lee (chrislee35 at gmail) - (C) 2009 
We use the RADIX functionality of the LIBGDS library (http://libgds.info.ucl.ac.be/)





**** Installation:

To install for all users, run the following command from within the source 
folder as root:

python setup.py install



It is also possible to install for the current user only. Use the following 
command: 

python setup.py install --home=~

This will install the module to some folder under the user's home directory. 
In this case, to import the module inside Python, you need to either set 
PYTHONPATH environmental variable, or alternatively, add the following code 
to the start of your python script:

import sys
sys.path.append('the_local_pythonlib_directory')    # something like /home/user/lib/python/
import PyASN 




**** Example usage:

import PyASN
p = PyASN.new('ipasndat_sample')   # see below for more info
print p.records                    # should print 314216
print p.Lookup('4.2.2.4')	   # should print 3356, the ASN for this IP

p = None 			   # free module memory (if desired)



Please note that the ipasndat_file is a text file containg lines of this format:
"CIDR/MASK\tASN"

e.g.:
192.9.9.0/24	90


A sample file is included in the package; I have seperate python scripts that 
can generate these IPASNDAT files from the RIB files available at archive.routeviews.org.





**** NOTE  on LIBGDS:

To avoid dependency on the library, and to enable simple build of this module 
on both Windows (MSVC) & Linux, the required source files from the libgds 
package have been copied into the package. 

They have also been slightly modified ('inline' keyword removed in sources; 
changes to types.h; parts of stream.c remarked) to enable building on 
Windows. The RADIX functionality is not effected by these changes. 


