// Python extension module that returns the autonomous system number for any given IP address 
//
// Based on code design by (C) 2009 Dr. Christopher Lee (chrislee35 at gmail)
// Author: Hadi Asghari (hd dot asghari at gmail) of TUDelft.nl
// Version 1.2 @27-11-2009   (v1.0 05-11-2009)
// 
//
// 1. This version uses a RADIX tree to store the IP-ASN mapping data.
// 2. It reads a text file containing "CIDR/MASK\tASN" lines; 
//    these files can be generated from routeviews.org RIB files using available scripts
// 
//
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the Lesser GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// Lesser GNU General Public License for more details.
// 
// You should have received a copy of the Lesser GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.


#ifndef _MSC_VER
#include <Python.h>
#include <structmember.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <assert.h>


#include "libgds/gds.h"
#include "libgds/radix-tree.h"



#ifdef _MSC_VER  
// Windows/VS specific code 
#undef _MSC_VER 			 // stop complaints about python.lib in following files
#include <C:\Python26\include\python.h>
#include <C:\Python26\include\structmember.h>
#endif



//////////////////////////////////////////////////////////////////////////////////////////////////////////
// IP helper methods

struct cidrstruct {
	unsigned int network;
	unsigned char bits;
};

#define VALID_IP(IP) ((IP[0]<256) && (IP[1]<256) && (IP[2]<256) && (IP[3]<256))
#define BUILD_IP(IP) ((IP[0]<<24) | (IP[1]<<16) | (IP[2]<<8) | IP[3])

int cidr2ipbits(const char* cidrstr, struct cidrstruct* cidr) {
	if(cidrstr == NULL)
		return 0;
	unsigned int IP1[4];
	int maskbits = 32;	// if using CIDR IP/mask format 

	// Try parsing IP/mask, CIDR format 
	if (strchr(cidrstr, '/') && (sscanf(cidrstr, "%u.%u.%u.%u/%d", &IP1[0], &IP1[1], &IP1[2], &IP1[3], &maskbits) == 5)
		&& VALID_IP(IP1) && (maskbits >= 1) && (maskbits <= 32))
	{
		cidr->network = BUILD_IP(IP1) & (~((1 << (32-maskbits))-1) & 0xFFFFFFFF);
		cidr->bits = maskbits;
		return 1;
	}
	else if ((sscanf(cidrstr, "%u.%u.%u.%u", &IP1[0], &IP1[1], &IP1[2], &IP1[3]) == 4) && VALID_IP(IP1))
	{
		cidr->network = BUILD_IP(IP1);
		cidr->bits = 32;
		return 1;
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct {
	PyObject_HEAD
	//PyObject *name; 
	int records;
	gds_radix_tree_t *radix ; 
} ip_asn_db;


static void ip_asn_db_dealloc(ip_asn_db* self)
{	
	if (self->radix  != NULL) 
		radix_tree_destroy( &(self->radix) );

	self->ob_type->tp_free((PyObject*)self);
}


static PyObject* ip_asn_db_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	ip_asn_db *self;
	self = (ip_asn_db *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->radix = NULL;
		self->records = 0;
	}
	return (PyObject *)self;
}


static int init_db(ip_asn_db *self, const char *fname) 
{
	FILE *ccfd = fopen(fname,"rt");
	if(ccfd == NULL) {
		PyErr_SetString(PyExc_IOError, "Could not open the file."); 
		return -1; 	
	}

	self->radix = radix_tree_create(32, NULL);
	self->records = 0;
	char buf[512], *p;
	struct cidrstruct cidr;

	while(fgets(buf,512,ccfd) != NULL) 
	{	
		if (buf[0] == ';')
			continue; // skip lines starting with semicolumn
		
		bool parse_success = false;

		if ( (p=strchr(buf,'\t')) != NULL ) 
		{				
			*p = 0;		
			int asni = atoi( (p+1) );
			if (asni != 0 && cidr2ipbits(buf,&cidr) != 0) 
			{
				radix_tree_add(self->radix, cidr.network, cidr.bits, (void*)asni);
				parse_success = true;
				self->records++;
			}
		}

		if (!parse_success) { 
			radix_tree_destroy(&self->radix);
			sprintf(buf, "Error encountered while parsing IPASNDB file (line %d).", self->records + 1);
			PyErr_SetString(PyExc_IOError, buf); 
			return -1; 
		}
	}

	fclose(ccfd);
	return 0;
}


static PyMemberDef ip_asn_db_members[] = {
	//{"name", T_OBJECT_EX, offsetof(ip_asn_db, name), 0, "DB filename"},
	{"records", T_INT, offsetof(ip_asn_db, records), 0, "Number of records read from DB"},
	{NULL}  
};


// Lookup the Autonomous System Number an IP address belongs to. Also returns the IP block.
static PyObject* ip_asn_db_lookup(ip_asn_db* self , PyObject *args)  
{
	const char *ip;
	if (!PyArg_ParseTuple(args, "s", &ip)) 
		return NULL;


	if (self->radix == NULL) {
		PyErr_SetString(PyExc_AssertionError, "Invalid object state!");
		return NULL;
	}

	struct cidrstruct cidr;
	if(cidr2ipbits(ip,&cidr) == 0) 	{
		PyErr_SetString(PyExc_RuntimeError, "Malformed IP address.");
		return NULL;
	}

	void *res = radix_tree_get_best(self->radix, cidr.network, cidr.bits);

	return (res != NULL) ? Py_BuildValue("i", res) : Py_BuildValue("z", NULL);
}



static PyMethodDef ip_asn_db_methods[] = {
	{"Lookup",  (PyCFunction)ip_asn_db_lookup, METH_VARARGS, "Returns the Autonomous System Number an IP address belongs to."},
	{NULL, NULL, 0, NULL}        
};


static PyTypeObject ip_asn_db_Type = {
	PyObject_HEAD_INIT(NULL)
	0,							//ob_size
	"PyASN",			        //tp_name
	sizeof(ip_asn_db),          //tp_basicsize
	0,							//tp_itemsize
	(destructor)ip_asn_db_dealloc, //tp_dealloc
	0,                         //tp_print
	0,                         //tp_getattr
	0,                         //tp_setattr
	0,                         //tp_compare
	0,                         //tp_repr
	0,                         //tp_as_number
	0,                         //tp_as_sequence
	0,                         //tp_as_mapping
	0,                         //tp_hash 
	0,                         //tp_call
	0,                         //tp_str
	0,                         //tp_getattro
	0,                         //tp_setattro
	0,                         //tp_as_buffer
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, //tp_flags
	"IP to ASN lookup - database object",  // tp_doc 
	0,							// tp_traverse 
	0,							// tp_clear 
	0,							// tp_richcompare 
	0,							// tp_weaklistoffset 
	0,							// tp_iter 
	0,							// tp_iternext 
	ip_asn_db_methods,          // tp_methods 
	ip_asn_db_members,			// tp_members 
	0,							// tp_getset 
	0,							// tp_base 
	0,							// tp_dict 
	0,							// tp_descr_get 
	0,							// tp_descr_set 
	0,							// tp_dictoffset 
	0,							// tp_init //(initproc)ip_asn_db_init,      
	0,							// tp_alloc 
	ip_asn_db_new,				// tp_new 
};


static PyObject* PyASN_new_Py(PyObject* self, PyObject *args) {
	ip_asn_db* asndb;
	const char* fname;

	if (!PyArg_ParseTuple(args, "s", &fname)) 
		return NULL;  

	asndb = PyObject_New(ip_asn_db, &ip_asn_db_Type);

	// the object's init method (ip_asn_db_init) was not getting called, so I replaced it with a manual call
	
	if (init_db(asndb, fname) == -1) {
		return NULL;
	}
	
	return (PyObject*)asndb ;
}


static PyMethodDef module_methods[] = {
	{"new", PyASN_new_Py, 1, "PyASN Constructor"},
	{NULL}  
};


PyMODINIT_FUNC initPyASN()
{
	PyObject* m;

	ip_asn_db_Type.tp_new = PyType_GenericNew;
	if (PyType_Ready(&ip_asn_db_Type) < 0)
		return;

	m = Py_InitModule("PyASN", module_methods); 

	//remarked this as we don't directly expose type
	//Py_INCREF(&ip_asn_db_Type);
	//PyModule_AddObject(m, "new", (PyObject *)&ip_asn_db_Type); 
}
