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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * SSH helper class.
 * This class lets you fetch the SSH host key fingerprint belonging to a server,
 * parsing it and returning the result.
 * 
 * @author Oliver Gasser
 *
 */
public class Ssh {

	// The property needed to determine the SSH command line and options file
	private static Properties properties = null;
	static {
		try {
			properties = new Properties("/opt/apache-tomcat/webapps/crossbear.properties");
		} catch (IOException e) {
		}		
	}

	// Enum specifying the various SSH key types
	public static enum KeyType {
		KEY_RSA1,
		KEY_RSA,
		KEY_DSA,
		KEY_ECDSA,
		KEY_RSA_CERT,
		KEY_DSA_CERT,
		KEY_ECDSA_CERT,
		KEY_RSA_CERT_V00,
		KEY_DSA_CERT_V00,
		KEY_UNSPEC
	}
	
	// Nid curve for ECDSA keys
	private static final int NID_X9_62_prime256v1 = 415;
	private static final int NID_secp384r1 = 715;
	private static final int NID_secp521r1 = 716;
	
	// Pattern matching OpenSSH fingerprint debug output
	private static final Pattern FP_PATTERN = Pattern.compile("debug1: Server host key: .*? (.*)");

	/**
	 * Converts the key type enumeration (including Nid for ECDSA keys)
	 * to the string from the SSH specification.
	 * This function is mostly inspired by the OpenSSH 6.1p1 implementation in key.c:
	 * key_ssh_name_from_type_nid(int type, int nid)
	 * 
	 * @param keyType Key type as enum
	 * @param nid Nid for ECDSA keys, for other keys its value can be arbitrary
	 * @return String representation for the SSH key type according to the specification
	 */
	@SuppressWarnings("incomplete-switch")
	public static String keyTypeToString(KeyType keyType, int nid) {
		
		switch (keyType) {
		case KEY_RSA:
			return "ssh-rsa";
		case KEY_DSA:
			return "ssh-dss";
		case KEY_RSA_CERT_V00:
			return "ssh-rsa-cert-v00@openssh.com";
		case KEY_DSA_CERT_V00:
			return "ssh-dss-cert-v00@openssh.com";
		case KEY_RSA_CERT:
			return "ssh-rsa-cert-v01@openssh.com";
		case KEY_DSA_CERT:
			return "ssh-dss-cert-v01@openssh.com";
		case KEY_ECDSA:
			switch (nid) {
			case NID_X9_62_prime256v1:
				return "ecdsa-sha2-nistp256";
			case NID_secp384r1:
				return "ecdsa-sha2-nistp384";
			case NID_secp521r1:
				return "ecdsa-sha2-nistp521";
			default:
				break;
			}
			break;
		case KEY_ECDSA_CERT:
			switch (nid) {
			case NID_X9_62_prime256v1:
				return "ecdsa-sha2-nistp256-cert-v01@openssh.com";
			case NID_secp384r1:
				return "ecdsa-sha2-nistp384-cert-v01@openssh.com";
			case NID_secp521r1:
				return "ecdsa-sha2-nistp521-cert-v01@openssh.com";
			default:
				break;
			}
			break;
		}
		return "ssh-unknown";
	}
	
	/**
	 * Fetches the SSH host key fingerprint from a remote server and parses it into
	 * a Fingerprint object. 
	 * 
	 * @param ip IP address for the remote server
	 * @param port Port number for the remote server
	 * @param keyType Key type which should be fetched
	 * @param nid Nid for ECDSA keys, for other keys its value can be arbitrary
	 * @param timeoutMs Timeout in milliseconds after which the fetching process will be stopped
	 * @return Fingerprint object with fingerprint from server (null if a problem occurred)
	 * and the current time
	 */


        /*
	  TODO: think about replacing this with native SSH code. Candidates?
	 */
	public static Fingerprint fetchSshFp(InetAddress ip, int port, KeyType keyType, int nid, long timeoutMs) {

		// Fingerprint result
		Fingerprint result;
		
		Runtime runtime = Runtime.getRuntime();
		Process process = null;
		try {
			// Specify keytype, port, IP and start the OpenSSH process
			process = runtime.exec(properties.getProperty("ssh.cmd") + " -F " + properties.getProperty("ssh.configfile")
					+ " -o HostKeyAlgorithms=" + Ssh.keyTypeToString(keyType, nid) + " -p " + port + " " + ip.getHostAddress());
		} catch (IOException e) {
			Logger.dumpExceptionToFile(properties.getProperty("logging.dir") + "/fourhundredfourtythree.Ssh.fetchSshFp.error", e);
		}
		
		// Start the worker for timeout detection
		Worker worker = new Worker(process);
		worker.start();
		try {
			worker.join(timeoutMs);
		} catch (InterruptedException e) {
			// Interrupt the timeout thread when the current thread is interrupted
			worker.interrupt();
			Thread.currentThread().interrupt();
			Logger.dumpExceptionToFile(properties.getProperty("logging.dir") + "/fourhundredfourtythree.Ssh.fetchSshFp.error", e);
		} finally {
			// Parse the result retrieved from the process and stop it
			result = parseFp(process);
			process.destroy();
		}
		return result;
	}
	
	/**
	 * Parses stderr of the SSH process to extract the server's fingerprint. 
	 * 
	 * @param process SSH process whose stderr output should be parsed
	 * @return Fingerprint object with current time and extracted fingerprint
	 */
	private static Fingerprint parseFp(Process process) {
		String extracted = null;
		// SSH's DEBUG messages are written to stderr
		BufferedReader b = new BufferedReader(new InputStreamReader(process.getErrorStream()));
		try {
			for (String temp = b.readLine(); temp != null; temp = b.readLine()) {
				// Check if one line matches and extract the fingerprint
				Matcher m = FP_PATTERN.matcher(temp);
				if (m.matches()) {
					extracted = m.group(1);
				}
			}
		} catch (IOException e) {
			Logger.dumpExceptionToFile(properties.getProperty("logging.dir") + "/fourhundredfourtythree.Ssh.parseFp.error", e);
		}
		
		return new Fingerprint(extracted, new Timestamp(System.currentTimeMillis()));
	}
	
	/**
	 * Helper class implementing the timeout thread.
	 * 
	 * @author Oliver Gasser
	 *
	 */
	private static class Worker extends Thread {
		private final Process process;

		private Worker(Process process) {
			this.process = process;
		}

		public void run() {
			try {
				process.waitFor();
			} catch (InterruptedException ignore) {
				return;
			}
		}
	}
}
