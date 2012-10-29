/*
    This file is part of Crossbear.

    Crossbear is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Crossbear is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Crossbear.  If not, see <http://www.gnu.org/licenses/>.

    Original authors: Thomas Riedmaier, Ralph Holz (TU Muenchen, Germany)
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
