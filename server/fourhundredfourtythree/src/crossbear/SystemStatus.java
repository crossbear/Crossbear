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

    Original authors: Thomas Riedmaier, Ralph Holz (TU München, Germany)
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
