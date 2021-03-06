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

import java.lang.Exception;

/**
 * This class implements an exception that is to be thrown in case our
 * traceroute implementation is unable to produce a well-formed trace.
 * 
 * @author Ralph Holz
 * 
 */
public class TraceException extends Exception {

    String[] trace;

    public TraceException(String desc, String[] trace) {
	super(desc);
	this.trace = trace;
    }
}