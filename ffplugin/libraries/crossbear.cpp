/*!
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

/* 
 * The crossbear.dll exports a "ping"-function that can be called from Javascript using c-types
 * to ping an IP with a specified Time-To-Live. It reads and replies with UTF-16 Strings since
 * this is Javascript's native Character encoding. Pinging of both IPv4 and IPv6-Addresses is
 * supported.
 */

#include "stdafx.h"

/*!
 * \brief
 * Get the default CodePage of the current system
 * 
 * \returns
 * The identifier of the current system's codepage (e.g. 1252 for ANSI Latin 1; Western European (Windows))
 * 
 * \see
 * http://www.torsten-horn.de/techdocs/encoding.htm | http://msdn.microsoft.com/en-us/library/windows/desktop/dd317756%28v=vs.85%29.aspx
 */
int getCurrentSystemCodePage(){
	WCHAR szCodePage[10];
	int cch= GetLocaleInfoW(
		GetSystemDefaultLCID(), // or any LCID you may be interested in
		LOCALE_IDEFAULTCODEPAGE,
		szCodePage,
		sizeof(szCodePage)/sizeof(WCHAR));

	return cch>0 ? _wtoi(szCodePage) : 0;
}

/*!
 * \brief
 * Convert a std::string into a UTF-16 wstring
 * 
 * \param s
 * The string to convert
 * 
 * \returns
 * The UTF-16-wstring-version of "s"
 */
std::wstring s2ws(const std::string& s)
{
	int slength = (int)s.length() + 1;

	// Get the length of s when it is converted to a wstring
	int codepage = getCurrentSystemCodePage();
	int len = 1+ MultiByteToWideChar(codepage, 0, s.c_str(), slength, 0, 0);

	// Create a buffer big enough to hold the wstring-version of "s"
	WCHAR* buf = new WCHAR[len];
	memset(buf,0,len*sizeof(WCHAR));

	// Convert "s" into its wstring-representation and place it in buf
	MultiByteToWideChar(codepage, 0, s.c_str(), slength, buf, len);

	// Create a wstring based on buf and return it
	std::wstring r(buf);
	delete[] buf;
	return r;

}

/*!
 * \brief
 * Definition of the IO_STATUS_BLOCK as included in the returns of IcmpSendEcho2 and Icmp6SendEcho2
 */
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/*!
 * \brief
 * Get the error-code of the last error that occured and get the corresponding error-message for it
 * 
 * \returns
 * The error-message corresponding to the last error-code as a wstring
 */
std::wstring getFormatedLastError(){

	// Get the error-code of the last error
	DWORD dw = GetLastError();

	// Get the error-message corresponding to that error-code
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
		(LPTSTR) &lpMsgBuf,
		0, NULL );

	// Convert the error-code into a number
	char errornum[10];
	_itoa (dw,errornum,10);

	// Concatenate the error-message and the error-code and return the result
	return s2ws(std::string(errornum)) +std::wstring(L": ")+ std::wstring((LPCTSTR)lpMsgBuf);
}

/*!
 * \brief
 * Put a wstring in a buffer that is provided by a calling Javascript function.
 * 
 * \param string
 * The string to put into the buffer
 * 
 * \param out
 * The buffer to put the string into
 * 
 * \param outSize
 * The maximum number of characters that can be written into "out".
 *
 * This function clears the buffer (sets its bytes to zero) and then copys "string" into "out" while paying attention not to write more than "outSize" characters.
 *
 * \remarks
 * WCHARS for Javascript API are UTF-16 encoded -> therefore size of out buffer is 2*outSize bytes and size of string is 2*(1+(int)string.length()) (including trailing 0)
 */
void outPutWstring(std::wstring string, WCHAR * out, int  outSize){

	// Clear the buffer
	memset(out,0,2*outSize);

	// Copy "string" into "out" while paying attention not to write more than "outSize" characters.
	memcpy(out,string.c_str(), min(2*outSize,2*(1+(int)string.length())));
}

/*!
 * \brief
 * This function pings an IPv6-Address with a specified Time-To-Live-value.
 * 
 * \param ai
 * The AddrInfo-representation of the TargetIP
 * 
 * \param ttl
 * The Time-To-Live-value to perform the ping with
 * 
 * \param out
 * The Buffer into which the result of the ping-command will be written
 * 
 * \param outSize
 * The maximum number of characters that can be written into "out"
 * 
 * \returns
 * True if the execution succeded and false otherwise. The following will be written in "out": "TARGET "+TargetIP if the target was reached, "HOP "+HopIP if an intermediate Host was reached or "NO_REPLY" if an execution error occurred. If an internal error occured, a message describing that error will be written.
 *
 * \remarks
 * ai will be Freed
 */
bool ping6(struct addrinfoW *ai, int ttl, WCHAR * out, int  outSize){
	// Create a handle to a hIcmpFile (required by Icmp6SendEcho2)
		HANDLE hIcmpFile = Icmp6CreateFile();
		if (hIcmpFile == INVALID_HANDLE_VALUE) {
			outPutWstring(std::wstring(L"Icmp6Createfile returned error: ")+getFormatedLastError(),out,outSize);

			// Free all allocated resources
			FreeAddrInfoW(ai);
			return false;
		}

		// A ICMP-request using IPv6 requires a source address: Get the system's IPv6 addresses
		ADDRINFOW hints;
		memset(&hints,0,sizeof(ADDRINFOW));
		hints.ai_family = AF_INET6;
		struct addrinfoW *lai;
		if(! (0==GetAddrInfoW(L"",NULL,&hints,&lai))){
			outPutWstring(std::wstring(L"Invalid Socket (Localhost) : ")+getFormatedLastError(),out,outSize);

			// Free all allocated resources
			FreeAddrInfoW(ai);
			IcmpCloseHandle(hIcmpFile);
			return false;
		}

		// Out of all of the system's IPv6-addresses: get a global IPv6 IP-Address for localhost
		struct addrinfoW *sourceGlobal = lai;
		while(sourceGlobal != NULL){
			sockaddr_in6 * a = (sockaddr_in6 *)sourceGlobal->ai_addr;
			if(IN6_IS_ADDR_GLOBAL(&a->sin6_addr)) break;
			sourceGlobal = sourceGlobal->ai_next;
		}

		// If there is none then there is no way to perform an ICMP-request on a IPv6-address -> abbort!
		if(sourceGlobal == NULL){
			outPutWstring(std::wstring(L"No global IPv6 interface found on localhost: ")+getFormatedLastError(),out,outSize);

			// Free all allocated resources
			FreeAddrInfoW(ai);
			FreeAddrInfoW(lai);
			IcmpCloseHandle(hIcmpFile);
			return false;
		}


		// Build the payload of the ICMP-request (mustn't be empty)
		char SendData[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

		// Allocate space for a single reply
		DWORD ReplySize = sizeof (ICMPV6_ECHO_REPLY) + sizeof (SendData) + 8 + sizeof(IO_STATUS_BLOCK);
		LPVOID ReplyBuffer = (VOID *) malloc(ReplySize);

		// Create a IP_OPTION_INFORMATION and set its TTL-field so Icmp6SendEcho2 will perform a ping with the correct TTL
		IP_OPTION_INFORMATION ipopts;
		memset(&ipopts,0,sizeof(ipopts));
		ipopts.Ttl = (unsigned char)ttl;

		//Try to perform the actual ping
		DWORD dwRetVal = Icmp6SendEcho2(hIcmpFile, NULL, NULL, NULL,(sockaddr_in6 *)sourceGlobal->ai_addr,  (sockaddr_in6 *)ai->ai_addr, SendData, sizeof (SendData), &ipopts, ReplyBuffer, ReplySize, 1000);
		if (dwRetVal == 0) {

			// In case it failed: Did it fail because of a timeout or because of a serious problem?
			bool success = false;
			DWORD lastError = GetLastError();
			if(IP_REQ_TIMED_OUT == lastError || IP_DEST_NET_UNREACHABLE ==  lastError ){
				// If it failed because of a Timeout return "NO_REPLY"
				outPutWstring(std::wstring(L"NO_REPLY"),out,outSize);
				success = true;
			}
			else{
				// If it failed because of a serious problem return a detailed description about the failure
				outPutWstring(std::wstring(L"Call to Icmp6SendEcho2 failed: ")+getFormatedLastError(),out,outSize);
			}

			// Free all allocated resources
			FreeAddrInfoW(ai);
			FreeAddrInfoW(lai);
			free(ReplyBuffer);
			IcmpCloseHandle(hIcmpFile);
			return success;
		}

		// Parse the reply on the ICMP-request
		PICMPV6_ECHO_REPLY pEchoReply = (PICMPV6_ECHO_REPLY) ReplyBuffer;

		/*
		 * Extract the address of the replying host
		 */
		// First: copy the reply data into a sockaddr_in6-struckture
		PIPV6_ADDRESS_EX pIP6Addr = &pEchoReply->Address;;
		sockaddr_in6 sock6;
		sock6.sin6_family = AF_INET6;
		sock6.sin6_flowinfo = pIP6Addr->sin6_flowinfo;
		sock6.sin6_port = pIP6Addr->sin6_port;
		sock6.sin6_scope_id = pIP6Addr->sin6_scope_id;
		memcpy(&sock6.sin6_addr, pIP6Addr->sin6_addr,sizeof(IN6_ADDR));

		// Second: convert it into human readable version
		WCHAR  ip6AddressString[256];
		DWORD bufferLenght = 256;
		if(0 != WSAAddressToStringW((LPSOCKADDR)&sock6,sizeof(sockaddr_in6),NULL,ip6AddressString,&bufferLenght)){
			outPutWstring(std::wstring(L"Call to WSAAddressToStringW failed: ")+getFormatedLastError(),out,outSize);

			// Free all allocated resources
			FreeAddrInfoW(ai);
			FreeAddrInfoW(lai);
			free(ReplyBuffer);
			IcmpCloseHandle(hIcmpFile);
			return false;
		}

		// Third: convert it into a wstring
		std::wstring hopName = std::wstring(ip6AddressString);

		/*
		 * Switch according to status of reply
		 */
		ULONG status = pEchoReply->Status;

		if(status == IP_SUCCESS){ 
			// Ping reached the target
			outPutWstring(std::wstring(L"TARGET ")+ hopName,out,outSize);
		}
		else if(status == IP_TTL_EXPIRED_TRANSIT || status == IP_TTL_EXPIRED_REASSEM){ 
			// Ping got a reply from a hop on the way to target
			outPutWstring(std::wstring(L"HOP ")+ hopName,out,outSize);
		}
		else{ 
			// Something didn't work
			outPutWstring(std::wstring(L"NO_REPLY"),out,outSize);
		}

		// Free all allocated resources
		free(ReplyBuffer);
		FreeAddrInfoW(ai);
		FreeAddrInfoW(lai);
		IcmpCloseHandle(hIcmpFile);
		return true;
}

/*!
 * \brief
 * This function pings an IPv4-Address with a specified Time-To-Live-value.
 * 
 * \param ai
 * The AddrInfo-representation of the TargetIP
 * 
 * \param ttl
 * The Time-To-Live-value to perform the ping with
 * 
 * \param out
 * The Buffer into which the result of the ping-command will be written
 * 
 * \param outSize
 * The maximum number of characters that can be written into "out"
 * 
 * \returns
 * True if the execution succeded and false otherwise. The following will be written in "out": "TARGET "+TargetIP if the target was reached, "HOP "+HopIP if an intermediate Host was reached or "NO_REPLY" if an execution error occurred. If an internal error occured, a message describing that error will be written.
 *
 * \remarks
 * ai will be Freed
 */
bool ping4(struct addrinfoW *ai, int ttl, WCHAR * out, int  outSize){
	
		// Create a handle to a hIcmpFile (required by IcmpSendEcho2)
		HANDLE hIcmpFile = IcmpCreateFile();
		if (hIcmpFile == INVALID_HANDLE_VALUE) {
			outPutWstring(std::wstring(L"IcmpCreatefile returned error: ")+getFormatedLastError(),out,outSize);

			// Free all allocated resources
			FreeAddrInfoW(ai);
			return false;
		}

		// Build the payload of the ICMP-request (mustn't be empty)
		char SendData[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

		// Allocate space for a single reply
		DWORD ReplySize = sizeof (ICMP_ECHO_REPLY) + sizeof (SendData) + 8 + sizeof(IO_STATUS_BLOCK);
		LPVOID ReplyBuffer = (VOID *) malloc(ReplySize);

		// Convert the IP-Address into the correct format
		IPAddr ipaddr;
		memcpy(&ipaddr, &((sockaddr_in *)ai->ai_addr)->sin_addr, sizeof(ipaddr));

		// Create a IP_OPTION_INFORMATION and set its TTL-field so IcmpSendEcho2 will perform a ping with the correct TTL
		IP_OPTION_INFORMATION ipopts;
		memset(&ipopts,0,sizeof(ipopts));
		ipopts.Ttl = (unsigned char)ttl;

		//Try to perform the actual ping
		DWORD dwRetVal = IcmpSendEcho2(hIcmpFile, NULL, NULL, NULL,  ipaddr, SendData, sizeof (SendData), &ipopts, ReplyBuffer, ReplySize, 1000);
		if (dwRetVal == 0) {

			// In case it failed: Did it fail because of a timeout or because of a serious problem?
			bool success = false;
			DWORD lastError = GetLastError();
			if(IP_REQ_TIMED_OUT == lastError || IP_DEST_NET_UNREACHABLE ==  lastError ){
				// If it failed because of a Timeout return "NO_REPLY"
				outPutWstring(std::wstring(L"NO_REPLY"),out,outSize);
				success = true;
			}
			else{
				// If it failed because of a serious problem return a detailed description about the failure
				outPutWstring(std::wstring(L"Call to IcmpSendEcho2 failed: ")+getFormatedLastError(),out,outSize);
			}

			// Free all allocated resources
			FreeAddrInfoW(ai);
			free(ReplyBuffer);
			IcmpCloseHandle(hIcmpFile);
			return success;
		}

		// Parse the reply on the ICMP-request
		PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY) ReplyBuffer;

		// Extract the address of the replying host
		struct in_addr ReplyAddr;
		ReplyAddr.S_un.S_addr = pEchoReply->Address;
		std::wstring hopName = s2ws(std::string(inet_ntoa(ReplyAddr)));

		// Switch according to status of reply
		ULONG status = pEchoReply->Status;

		if(status == IP_SUCCESS){
			// Ping reached the target
			outPutWstring(std::wstring(L"TARGET ")+ hopName,out,outSize);
		}
		else if(status == IP_TTL_EXPIRED_TRANSIT || status == IP_TTL_EXPIRED_REASSEM){
			// Ping got a reply from a hop on the way to target
			outPutWstring(std::wstring(L"HOP ")+ hopName,out,outSize);
		}
		else{
			// Something didn't work
			outPutWstring(std::wstring(L"NO_REPLY"),out,outSize);
		}

		// Free all allocated resources
		free(ReplyBuffer);
		FreeAddrInfoW(ai);
		IcmpCloseHandle(hIcmpFile);
		return true;

}

/*!
 * \brief
 * This function pings an IP-Address with a specified Time-To-Live-value.
 * 
 * \param targetIP
 * The textual representation of the IP-Address to ping (both IPv4 and IPv6 are accepted)
 * 
 * \param ttl
 * The Time-To-Live-value to perform the ping with
 * 
 * \param out
 * The Buffer into which the result of the ping-command will be written
 * 
 * \param outSize
 * The maximum number of characters that can be written into "out"
 * 
 * \returns
 * True if the execution succeded and false otherwise. The following will be written in "out": "TARGET "+TargetIP if the target was reached, "HOP "+HopIP if an intermediate Host was reached or "NO_REPLY" if an execution error occurred. If an internal error occured, a message describing that error will be written.
 *
 * \remarks
 * Writing the "ping"-function in Javascript and calling the iphlpapi.dll (and others) using c-types turned out to be impossible. The reason for that is the fact that calling GetLastError() is not possible using c-types. Therefore it is implemented in c-code and compiled into the crossbear.dll.
 * 
 */
extern "C" __declspec( dllexport ) bool ping(WCHAR * targetIP, int ttl, WCHAR * out, int  outSize){

	// Validate the Time-To-Live-Parameter: less than 1 is invalid and more than 255 doesn't make sense and might cause _itow problems
	if(ttl<1 || ttl>255){
		outPutWstring(std::wstring(L"TTL Parameter invalid"),out,outSize);
		return false;
	}

	// Verify if targetIP is a valid address if yes convert it into a addrinfo-struct
	struct addrinfoW *ai;
	if(! (0==GetAddrInfoW(targetIP,NULL,NULL,&ai))){
		outPutWstring(std::wstring(L"could not parse IP Address : ")+getFormatedLastError(),out,outSize);
		return false;
	}

	// Check if the IP-version of the targetIP is v6 ...
	if(ai->ai_family == AF_INET6){

		// ... and if it is perform a ping using ICMPv4
		return ping6(ai, ttl, out, outSize);

	}

	// Check if the IP-version of the targetIP is v4 ...
	else if(ai->ai_family == AF_INET){

		// ... and if it is perform a ping using ICMPv6
		return ping4(ai, ttl, out, outSize);

	}

	// In case the passed address is neither IPv4 nor IPv6: Return an error message
	outPutWstring(std::wstring(L"Unknown type of IPAddress"),out,outSize);
	FreeAddrInfoW(ai);
	return false;
}