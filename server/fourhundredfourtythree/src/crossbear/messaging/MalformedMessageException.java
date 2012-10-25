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

package crossbear.messaging;

import java.lang.Exception;

/**
 * This class implements an exception that is to be thrown when a
 * message that has been received from a Crossbear entity is in some
 * way malformed (e.g. of wrong type).
 * 
 * @author Ralph Holz
 * 
 */
public class MalformedMessageException extends Exception {

    public MalformedMessageException(String desc) {
	super(desc);
    }

}