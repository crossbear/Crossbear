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
