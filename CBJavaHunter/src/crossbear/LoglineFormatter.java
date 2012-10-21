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

import java.util.logging.SimpleFormatter;
import java.util.logging.LogRecord;


/** 
   This is the most stupid and yet necessary work-around just because SimpleFormatter won't let you choose to write each log entry to a
   single line

   @author Ralph Holz
*/
public class LoglineFormatter extends SimpleFormatter {
    // make this work on both UNIX and Windows
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    /**
     * overwrite SimpleFormatter.format()
     * @param LogRecord entry to be logged as LogRecord
     * @return String the LogRecord data formatted as a String
     * @overwrite private String format(LogRecord record)
     * @see java.util.logging.SimpleFormatter
     */
    public String format(LogRecord record) {
	return new java.util.Date() + " " + record.getLevel() + " " + record.getMessage() + LINE_SEPARATOR;
    }

}