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
*/

package crossbear;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.sql.SQLException;

import crossbear.messaging.HuntingTaskReply;
import crossbear.messaging.HuntingTaskReplyKnownCertChain;
import crossbear.messaging.HuntingTaskReplyNewCertChain;
import crossbear.messaging.Message;


/**
 * The HTRProcessor takes as input a InputStream whose content is supposed to be an array of HuntingTaskReply-messages. It attempts to decode the messages one-by-one and - in case they are valid -
 * adds them to the database.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class HTRProcessor {

	/**
	 * Try to decode an InputStream as array of HuntingTaskReply-messages. If that worked check if the HuntingTaskReplies are valid and - in case they are - add them to the database.
	 * 
	 * @param in The InputStream to decode
	 * @param cm The CertificateManager that it will use for processing or storing certificates
	 * @param db The Database connection to use
	 * @throws IOException
	 * @throws InvalidParameterException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws SQLException
	 * @throws CertificateException
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 */
	public HTRProcessor(InputStream in, CertificateManager cm, Database db) throws IOException, InvalidParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SQLException, CertificateException, InvalidAlgorithmParameterException, KeyStoreException {
		
		// Try to read an array of crossbear.Message from the InputStream
		while (true) {
		
			// The first byte of each crossbear.Message is its type
			int messageType = in.read();
			
			// In case the last message has been read in.read() returned "-1" -> we are done
			if(messageType == -1){
				break;
			}
			
			// Verify message type: It has to be either MESSAGE_TYPE_TASK_REPLY_KNOWN_CERT or MESSAGE_TYPE_TASK_REPLY_NEW_CERT
			if (messageType != Message.MESSAGE_TYPE_TASK_REPLY_KNOWN_CERT && messageType != Message.MESSAGE_TYPE_TASK_REPLY_NEW_CERT) {
				throw new IllegalArgumentException("The provided messageType " + messageType + " was not expected");
			}

			// Read the message's length field (which are bytes 2 & 3 of each crossbear.Message)
			byte[] messageLengthB = Message.readNBytesFromStream(in,2);
			int messageLength = Message.byteArrayToInt(messageLengthB);

			
			// Try to read one message from the input (validation is performed inside the message's constructor)
			byte[] raw = Message.readNBytesFromStream(in, messageLength-3);
			HuntingTaskReply reply;
			if(messageType == Message.MESSAGE_TYPE_TASK_REPLY_KNOWN_CERT){
				reply = new HuntingTaskReplyKnownCertChain(raw,db);
			} else{
				reply = new HuntingTaskReplyNewCertChain(raw,cm,db);
			}
			
			// If the constructor didn't throw any Exceptions: Store the reply in the database
			reply.storeInDatabase(db);
			
		}
	}
}
