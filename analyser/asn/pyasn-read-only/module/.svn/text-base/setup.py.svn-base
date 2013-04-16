import distutils.core 
import platform
libs = []
if platform.system() == 'Windows': libs.append('python26')

distutils.core.setup(name='PyASN',
      version='1.2',
      description='Python module to do IP to ASN lookups',
      author = 'Hadi Asghari',
      author_email = 'hd dot asghari at g-mail',
      url = '' ,	  
      ext_modules=
	  [
	  distutils.core.Extension('PyASN', 
		['pyasn.cpp', 'libgds/array.c', 'libgds/enumerator.c', 'libgds/gds.c', 'libgds/memory.c', 'libgds/radix-tree.c', 'libgds/stack.c', 'libgds/stream.c', 'libgds/trie.c']
		, include_dirs=['.'], extra_compile_args=['-w'], libraries=libs
		)
	  ]
      )
