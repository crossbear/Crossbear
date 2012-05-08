/*
 * Copyright (c) 2012, Thomas Riedmaier, TU München
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

import java.security.InvalidParameterException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

/**
 * The SystemStatus class defines an interface to access information on the current status of the Crossbear system.
 * 
 * @author Thomas Riedmaier
 *
 */
public class SystemStatus {
	

	/**
	 * Get and return the number of Hunting Tasks that are currently active
	 * 
	 * @param db The database connection to use
	 * @return A status text containing the information of how many Hunting Tasks are currently active
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public static String getActiveHuntingTasks(Database db) throws InvalidParameterException, SQLException{
		
		// Perform a query to get the number of active Hunting Tasks
		Object[] params = { };
		ResultSet rs = db.executeQuery("SELECT COUNT(*) AS c FROM HuntingTasks WHERE active = 'true'", params);
		
		// If the result is empty then something went wrong
		if (!rs.next()) {
			throw new SQLException("ResultSet was empty!");
		}
		
		// Return the number of active Hunting Tasks
		return "Active Hunting Tasks: "+rs.getString("c");
	}
	
	/**
	 * Estimate and return the number of Hunters that are currently active (i.e. numbers of IPs that requested the Hunting Task list up to half an hour ago)
	 * 
	 * @param db The database connection to use
	 * @return A status text containing the information of how many Hunters are currently active
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public static String getActiveHunters(Database db) throws InvalidParameterException, SQLException{
		
		// Perform a query to get the number of active Hunters
		Object[] params = {new Timestamp(System.currentTimeMillis()-30*60*1000) };
		ResultSet rs = db.executeQuery("SELECT COUNT(DISTINCT RequestingIP) AS c FROM HuntingTaskRequests WHERE TimeOfRequest > ?", params);
		
		// If the result is empty then something went wrong
		if (!rs.next()) {
			throw new SQLException("ResultSet was empty!");
		}
		
		// Return the number of active Hunters
		return "Active Hunters: "+rs.getString("c");
		
	}
	
	/**
	 * Return an HTML encoded overview of the current status of the Crossbear system
	 * 
	 * @param db The database connection to use
	 * @return An HTML encoded String that describes the current status of the Crossbear system
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public static String getStatusHTML(Database db) throws InvalidParameterException, SQLException{
		String re = "";
		
		re += getActiveHuntingTasks(db) + "<br>\r\n";
		
		re += getActiveHunters(db) + "<br>\r\n";
		
		return re;
	}
}
