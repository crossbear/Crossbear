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

import java.io.IOException;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import crossbear.messaging.Message;

/**
 * This class provides Traceroute-like functionality. Unfortunately, it is not possible to do so from within Java-code because of limitations of the Java-API.
 * 
 * The current workaround to get around those, is to execute the system's "ping" and "ping6" commands, read their output and use it to simulate Traceroutes. 
 * 
 * @author Thomas Riedmaier
 *
 */
public class Tracer {

    /**
     * For the task of locating a Mitm the information of what
     * PublicIP a client is on is very valuable while the
     * information which private IP it uses is of no use at all.
     * 
     * This function removes all private IPs from the Traceroute's
     * output and replaces them with the client's publicIP
     * 
     * @param ownPublicIP
     *            The client's publicIP
     * @param tracerouteOutput
     *            The output of the CBTracer.traceroute-function
     * @returns publicIP.concat(tracerouteOutput) but without private IPs
     */
    public static String addOwnPublicIPAndRemovePrivateIPs(InetAddress ownPublicIP, String tracerouteOutput) {
	// Split up the tracerouteOutput into the HOP-lines
	LinkedList<String> arrayOfHops = new LinkedList<String>(Arrays.asList(tracerouteOutput.split("\n")));
	LinkedList<String> cleanedArrayOfHops = new LinkedList<String>();

	// Define a pattern that matches private IPs
	Pattern privateIPRegex = Pattern.compile("\\A(fe8|fe9|fea|feb|fec|fed|fee|fef|fc|fd|169\\.254\\.|10\\.|172\\.16\\.|172\\.17\\.|172\\.18\\.|172\\.19\\.|172\\.20\\.|172\\.21\\.|172\\.22\\.|172\\.23\\.|172\\.24\\.|172\\.25\\.|172\\.26\\.|172\\.27\\.|172\\.28\\.|172\\.29\\.|172\\.30\\.|172\\.31\\.|192\\.168\\.).*",Pattern.CASE_INSENSITIVE);

	// Go over all HOP-lines ...
	for (int i = 0; i < arrayOfHops.size(); i++) {

	    // ... and split them up to get all the IPs contained in that lines.
	    LinkedList<String> elementsOfCurrentHop = new LinkedList<String>(Arrays.asList(arrayOfHops.get(i).split("\\|")));
	    LinkedList<String> cleanedElementsOfCurrentHop = new LinkedList<String>();

	    // Then go through all of those IPs
	    for (int j = 0; j < elementsOfCurrentHop.size(); j++) {

		// And check if they are private
		if (!privateIPRegex.matcher(elementsOfCurrentHop.get(j)).matches()) {

		    // If not private: keep them
		    cleanedElementsOfCurrentHop.add(elementsOfCurrentHop.get(j));
		}

	    }

	    // After having finished the inspection of the HOP-line: rebuild it and add it to the cleaned output
	    if (cleanedElementsOfCurrentHop.size() > 0) {
		cleanedArrayOfHops.add(join(cleanedElementsOfCurrentHop, '|'));
	    }
	}

	// Take the cleaned output and append the client's
	// public IP to it (cleanedArrayOfHops will always
	// include the target's IP and therefore it will never
	// be empty)
	return ownPublicIP.getHostAddress() + "\n" + join(cleanedArrayOfHops, '\n');
    }

    /**
     * Scan the textual output of a "ping" or "ping6" command for IPs that don't match a reference IP.
     * 
     * @param pingOutput
     *            The textual output of a "ping" or "ping6" command to scan
     * @param referenceIP
     *            The IP to compare all found IPs with
     * @returns Null if no non-matching IP is found or the first non-matching IP
     * @throws UnknownHostException
     */
    private static InetAddress getFirstNonMatchIP(String pingOutput, InetAddress referenceIP) throws UnknownHostException {

	// Define a Regex that will match all IPs (and more)
	Pattern ipPat = Pattern.compile("[\\da-f]*([:\\.]+[\\da-f]+)+(::)?", Pattern.CASE_INSENSITIVE);

	// Use that Regex to find all IPs (and some other things like durations: "24.45"ms)
	Matcher m = ipPat.matcher(pingOutput);

	// Check if all found matches that are actually IPs match the referenceIP
	while (m.find()) {

	    // Get the whole match
	    String candidate = m.group();

	    // For each match check if it is a valid IP-Address and if it is compare it with the referenceIP ...
	    if (Message.isValidIPAddress(candidate)) {
		InetAddress candidateIP = InetAddress.getByName(candidate);
		if (!candidateIP.equals(referenceIP)) {

		    // ... and in case they are not equal return it
		    return candidateIP;
		}
	    }
	}

	// If no non-matching IP is found return null
	return null;
    }

    /**
     * Join all elements of a LinkedList of type E into a separator-separated String
     * 
     * This code was created by the use of http://snippets.dzone.com/posts/show/91
     * 
     * @param list A LinkedList of elements whose String-representations should be concatenated (e.g. "a"->"b"->"c")
     * @param separator The separator to put between the elements of the list (e.g. '|')
     * @return The String-concatenation of all elements of "list" separated by "separator"
     */
    private static <E> String join(LinkedList<E> list, char separator) {
		
	// Create an output buffer
	StringBuffer buffer = new StringBuffer();
		
	// Go through all elements of the list ...
	Iterator<E> iter = list.iterator();
	while (iter.hasNext()) {
			
	    // ... and append them to the output buffer.
	    buffer.append(iter.next());
			
	    // In case the element was not the last one in the list ...
	    if (iter.hasNext()) {
		// ... append a separator-char to the list.
		buffer.append(separator);
	    }
	}
		
	// Finally: return the buffer
	return buffer.toString();
    }

    /**
     * Perform a ping on a Unix/Linux system. This is currently done by executing "ping"/"ping6" and reading its output. Depending on that output it is then decided if the ping reached the host, a
     * intermediate hop or if an error occurred.
     * 
     * The command that will be executed is /bin/ping(6) -c 1 -n -W 1 -t "ttl" "ip"
     * 
     * @param ip
     *            The IP-Address to ping
     * @param ipVersion
     *            The version of the IP-Address (4 or 6)
     * @param ttl
     *            The Time-To-Live of the ping that should be sent
     * @returns "TARGET "+TargetIP if the target was reached, "HOP "+HopIP if an intermediate Host was reached or "NO_REPLY" if an error occurred during the execution of "ping"
     * @throws IOException
     */
    private static String ping(InetAddress ip, int ipVersion, int ttl) throws IOException {

	// Execute the "ping"/"ping6"-command
	ProcessBuilder processBuilder = new ProcessBuilder(new String[] { "/bin/ping" + ((ipVersion == 6) ? "6" : ""), "-c", "1", "-n", "-W", "1", "-t", String.valueOf(ttl), ip.getHostAddress() });
	Process process = processBuilder.start();

	// Get the command's output
	String pingOutput = Message.inputStreamToString(new SequenceInputStream(process.getInputStream(),process.getErrorStream()));
		
	// Check if all occurences of IPs inside the output match the IP that was pinged
	InetAddress firstNonMatchIP = getFirstNonMatchIP(pingOutput, ip);

	// Check if either the pattern "TTL" or "TIME TO LIVE" or "HOP LIMIT" appears
	Pattern ttlPat = Pattern.compile("TTL|TIME TO LIVE|HOP LIMIT", Pattern.CASE_INSENSITIVE);
	boolean containsTTL = ttlPat.matcher(pingOutput).find();

	// Check if the pattern "0%" (but not 100%) appears -> Indicates "no Packet loss" on unix systems
	Pattern zeroPercentPat = Pattern.compile("[^0]0%", Pattern.CASE_INSENSITIVE);
	boolean containsZeroPercent = zeroPercentPat.matcher(pingOutput).find();

	// If there was only the target's IP in the output and if the packet loss was 0% then the ping reached the target
	if ((firstNonMatchIP == null) && containsZeroPercent) {
	    return "TARGET " + ip.getHostAddress();

	    // If there was more than one IP in the output and it also contained a pattern indicating that the TTL was exceeded then the ping reached an intermediate hop
	} else if ((firstNonMatchIP != null) && containsTTL) {
	    return "HOP " + firstNonMatchIP.getHostAddress();

	    // All other cases mean that an error occurred.
	} else {
	    return "NO_REPLY";
	}

    }
    // How many hops should be taken into account before terminating the Traceroute?
    private int maxHops;

    // How many samples should be taken per hop (i.e. should be sent with the same TTL)
    private int samplesPerHop;

    /**
     * Create a new Tracer
     * 
     * @param maxHops Number of hops that should be taken into account before terminating the Traceroute
     * @param samplesPerHop Number of samples to be taken per hop (i.e. should be sent with the same TTL)
     */
    public Tracer(int maxHops, int samplesPerHop) {
	this.maxHops = maxHops;
	this.samplesPerHop = samplesPerHop;
    }

    /**
     * Perform a Traceroute on an IP. This function will call the Tracer.ping-function with increasing TTL-values. The Trace returned by this function will consist of one line per measured hop. If
     * more than one IP replied for the same TTL then the line will look like "IP1|IP2|...". If there was no reply from a HOP it won't be listed (and there will be no empty line either). This is
     * because of the fact that between two HOPs that reply there could possibly be a lot of HOPs that didn't reply and didn't decrease the TTL-value anyway.
     * 
     * @param ip
     *            The IP-Address to trace
     * @param ipVersion
     *            The version of the IP-Address (4 or 6)
     * @returns The Traceroute in the format described above
     * @throws TraceException
     * @throws IOException
     */
    public String traceroute(InetAddress ip, int ipVersion) throws TraceException, IOException {
	LinkedList<String> re = new LinkedList<String>();

	// Perform pings with an increasing TTL (starting at 1 and ending with self.MaxHops)
	hopLoop: for (int hopNum = 1; hopNum <= maxHops; hopNum++) {

	    LinkedList<String> samplesOfHop = new LinkedList<String>();
	    // For each TTL perform samplesOfHop-many Pings and see if more than one host replies
	    for (int sampleNum = 0; sampleNum < samplesPerHop; sampleNum++) {

		// Perform a ping with a given TTL and see whether it reached the Target, a Hop or no host at all
		String[] pingResult = ping(ip, ipVersion, hopNum).split(" ");
		switch (pingResult[0]) {
		case "HOP":
		    // If it reached a HOP add it to the current Hop's host-list (but don't add duplicates)
		    if (samplesOfHop.indexOf(pingResult[1]) < 0) {
			samplesOfHop.add(pingResult[1]);
		    }
		    break;
		case "TARGET":
		    // If it reached the Target we are done
		    break hopLoop;
		case "NO_REPLY":
		    break;
		default:
		    throw new TraceException("Received unexpected ping response: " + Arrays.deepToString(pingResult), pingResult);
		}
	    }

	    // For each HOP: Generate a "|"-seperated list of IPs that replied
	    if (samplesOfHop.size() > 0) {
		re.add(join(samplesOfHop, '|'));
	    }
	}

	// Finally add the Target's IP to the list of Hops (which will be transformed in a "\n"-seperated list) and return the trace
	return (join(re, '\n') + '\n' + ip.getHostAddress()).trim();
    };

}
