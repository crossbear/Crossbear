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

import java.lang.Exception;

/**
 * This is a wrapper class around all exceptions that can 
 * occur if the serialisation of a Message object fails.
 *
 * The purpose is to keep the abstract class Message free
 * of Exceptions that derived classes may need to know.
 *
 * @see crossbear.messaging.Message
 * @todo The cleaner way would probably be to refactor the
 * crossbear.messaging hierarchy.
 *  
 * @author Ralph Holz
 * 
 */
public class MessageSerializationException extends Exception {

    public MessageSerializationException(String desc, Exception e) {
	super(desc, e);
    }

}