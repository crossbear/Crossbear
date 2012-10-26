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

import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Date;

/**
 * The Logger is a class that provides logging of exceptions to files. This is useful since exceptions should not be displayed to the clients. Instead they should be made available to the programmer ;)
 * 
 * @author Thomas Riedmaier
 *
 */
public class Logger {

	/**
	 * Append a Exception's time of generation, its Message and its stackTrace into a log-file
	 * 
	 * @param logFileName The file to log to
	 * @param e The exception to log
	 */
	public static void dumpExceptionToFile(String logFileName, Exception e) {
		try {

			// Open the file into which the Exception should be logged
			FileWriter fstream = new FileWriter(logFileName, true);

			// The Exception's stackTrace can only be written into a PrintWriter: Create it ...
			final Writer result = new StringWriter();
			final PrintWriter printWriter = new PrintWriter(result);
			
			// ... and write the stackTrace into it.
			e.printStackTrace(printWriter);

			// Then write the Exception's time of generation, its Message and its stackTrace into the log-file
			fstream.write("\n-------------------" + new Date() + "-------------------------\n" + e.getLocalizedMessage() + "\n\n" + result.toString());

			// Flush and clos the output stream
			fstream.flush();
			fstream.close();

		} catch (Exception e2) {
			// This is already the exception-handling routine. If this function fails also: Don't do anything :(
		}
	}
}
