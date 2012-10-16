/*
 * Copyright (c) 2011, Thomas Riedmaier, TU München
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Crossbear nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THOMAS RIEDMAIER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package crossbear;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * Wrapper class for a java.util.Properties-object that was initialized with the content of a properties-file
 * 
 * @author Thomas Riedmaier
 *
 */
public class Properties {

	private java.util.Properties properties;

	/**
	 * Create a new Properties-object and initialize it with the content of a properties file.
	 * 
	 * @param propertyFileName The filename of the properties-file to initialize this object with
	 * @throws IOException
	 */
	public Properties(String propertyFileName) throws IOException{
		
		// Create a new Properties-object
		this.properties =  new java.util.Properties();
		
		// Open the properties-file
		InputStream is = new FileInputStream(propertyFileName);

		// Initialize the Properties-object with the content of the properties-file
		properties.load(is);
	    
		// Close the input-stream of the properties-file
	    is.close();
		
	}
	
	/* (non-Javadoc)
	 * @see java.util.Properties.getProperty(java.lang.String)
	 */
	public String getProperty(String key){
		return properties.getProperty(key);
	}
	
	/* (non-Javadoc)
	 * @see java.util.Properties.setProperty(java.lang.String, java.lang.String)
	 */
	public Object setProperty(String key, String value){
		return  properties.setProperty(key, value);
	}
	
	
}
