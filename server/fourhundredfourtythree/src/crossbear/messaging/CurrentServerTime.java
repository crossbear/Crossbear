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

package crossbear.messaging;

import java.io.IOException;
import java.io.OutputStream;
import java.sql.Timestamp;


/**
 * The CurrentServerTime-message is sent to the client every time a hunting task is sent to it. The message contains a Timestamp of the current server time and is used to give the client the ability
 * to sent Hunting Task Replies with a Timestamp that is at least roughly equal to the Timestamp the server would have recorded if it would have executed the Hunting Task at that time.
 * 
 * The structure of the CurrentServerTime-message is
 * - Header
 * - Timestamp of current server time (4 bytes)
 * 
 * @author Thomas Riedmaier
 * 
 */
public class CurrentServerTime extends Message {
	
	// The difference between the local time and the Crossbear server time in ms: cbServerTimeDiff = cbServerTime-localTime
	private final long cbServerTimeDiff;

	/**
	 * Create a new Message of Type MESSAGE_TYPE_CURRENT_SERVER_TIME
	 * 
	 * Please note: This function is meant to be executed on the server only!
	 */
	public CurrentServerTime() {
		super(Message.MESSAGE_TYPE_CURRENT_SERVER_TIME);
		
		// Since the code is executed locally on the server, there is no difference between the local time and the server time
		cbServerTimeDiff = 0;
	}

	/**
	 * Create a CurrentServerTime based on a byte[] that was sent by a server and is supposed to be a valid CurrentServerTime-message. The validity is checked within this function.
	 * 
	 * @param raw The byte[] to create the CurrentServerTime from
	 */
	public CurrentServerTime(byte[] raw){
		// Set the type of the message-object to "CurrentServerTime"
		super(Message.MESSAGE_TYPE_CURRENT_SERVER_TIME);

		// Make sure that the input - which is supposed to be a CurrentServerTime-message - has the correct length
		if (raw.length  != 4) {
			throw new IllegalArgumentException("The raw data array does not have the correct length: "+ raw.length);
		}
		
		// Calculate the difference between the local and the server clock and store it
		cbServerTimeDiff = (long)byteArrayToInt(raw) * 1000 -System.currentTimeMillis();
	}
	
	/**
	 * Get a Timestamp that is at least roughly equal to the server's current time
	 * 
	 * @return An estimation of the server's current local time. If this code is executed on the server it will return the exact value.
	 */
	public Timestamp getCurrentServerTime() {
		return new Timestamp(cbServerTimeDiff + System.currentTimeMillis());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws MessageSerializationException {

	    try {
		out.write(Message.intToByteArray((int) (getCurrentServerTime().getTime() / 1000)));
	    }
	    catch (Exception e) {
		throw new MessageSerializationException("Could not serialize server time", e);
	    }
	}

}
