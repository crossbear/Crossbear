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

/**
 * The CBTrustDecisionCache can be asked whether a certificate is known for a host and - in case it is - if it should be trusted. It will then give one of the CBTrustDecisionCacheReturnTypes as answer 
 */
var CBTrustDecisionCacheReturnTypes = {
	OK : 0,
	NOT_VALID : 1,
	CB_SERVER_OK : 2,
	CB_SERVER_NOT_VALID : 3,
	NOT_IN_CACHE : 4
};

/**
 * A CBTrustDecisionCacheEntry contains the information whether or not to trust a certificate for a specific host. Since this information is not infinitely valid each CBTrustDecisionCacheEntry also contains the information until when it is valid.
 * 
 * @param hash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
 * @param host The host that should or should not be trusted when sending a certificate with hash "hash"
 * @param trust True if the certificate with hash "hash" should be trusted when received from "host", else false
 * @param validUntil A Timestamp telling until when the trust-information given by this CBTrustDecisionCacheEntry should be considered valid
 * 
 * @author Thomas Riedmaier
 */
function CBTrustDecisionCacheEntry(hash, host, trust, validUntil) {
	this.hash = hash;
	this.host = host;
	this.trust = trust;
	this.validUntil = validUntil;
}

/**
 * Crossbear uses multilevel caching on information about certificate trust. This reduces the load on the Crossbear server on the one hand while on the other hand speeding up the page-loading tremendously. When a user observes a certificate for a
 * page for the first time it will be sent to the Crossbear server for verification and the result will be displayed to the user. The user will then decide whether he/she wants to trust that certificate for that host or not. This decision will be
 * stored in the local database (namely the certTrust-table), so future observations of the same certificate/host-combination can thus be handled without querying the Crossbear server.
 * 
 * However, there is always the possibility that a Mitm fooled the whole network e.g. because he placed himself right next to the original server. In that scenario, Crossbear would judge a forged Mitm-certificate as valid as long as the Mitm is in
 * place. Assuming that it is very hard to fool the whole network for a long time the Mitm will eventually cease sending his forged Certificate to the Crossbear server. Starting that very moment Crossbear will warn its users about the Mitm's
 * certificate. If a cert-trust decision would be valid infinitely the new findings about the Mitm's certificate would never reach the user. That's why each Entry in the local TDC has a validity. If that validity has expired the Cache
 * entry will be ignored and the Crossbear server will be contacted again.
 * 
 * Loading the information about whether or not to trust a certificate for a host from the database cache is rather slow. Therefore Crossbear uses a second cache that is placed inside a Javascript-object. Accessing this cache is much faster than
 * accessing the database. The Javascript-cache contains merely the last hand-full of Cache-Entries that were used. Most of the time a host is contacted more than once (e.g. because of Images, Stylesheets, Scripts, ...). All but the first access will
 * find a match in the Javascript-cache and therefore will be able to answer the question whether or not to trust a certificate for a host very quickly.
 * 
 * This class implements the local multilevel cache.
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
 * 
 * @author Thomas Riedmaier
 */
function CBTrustDecisionCache(cbFrontend) {
	this.cbFrontend = cbFrontend;

	// This is the Javascript-object that implements the first-level cache on the information whether or not a certificate should be trusted for a host.
	this.recentlyUsedCertificatesValidities = [];
	
	// This is the maximum size of the first-level cache. Since the cache will always be searched completely if a new host/cert is observed it should not be too big.
	this.maximumSizeOfRUCV = 10;

	// The SHA256-hash of the only certificate that will be trusted for connections to the Crossbear server. Setting this is important in order to prevent Mitm-attacks against the Crossbear server.
	this.cbServerCertHash = null;

	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbtrustdecisioncache_prototype_called) == 'undefined') {
		_cbtrustdecisioncache_prototype_called = true;

		/**
		 * Set the SHA256-hash value of the ONLY certificate that will be trusted on connections to the Crossbear server
		 * 
		 * @param hash The SHA256-hash of the only trusted certificate for the Crossbear server
		 */
		CBTrustDecisionCache.prototype.setCBServerCertHash = function setCBServerCertHash(hash) {
			self.cbServerCertHash = hash;
		};
		
		/**
		 * Add a new entry stating whether or not to trust a certificate for a specific host or not to the local cache.
		 * 
		 * @param hash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param host The host that should or should not be trusted when sending a certificate with hash "hash"
		 * @param trust True if the certificate with hash "hash" should be trusted when received from "host", else false
		 * @param validUntil A Timestamp telling until when the trust-information given by this CBTDCEntry should be considered valid
		 */
		CBTrustDecisionCache.prototype.add = function add(hash, host , trust, validUntil) {

			// 1) Add the entry to the database (=persistent) cache
			var sqlStatement = "INSERT OR REPLACE INTO certTrust ( CertHash, Host, Trust, ValidUntil) VALUES (:hash, :host, :trust, :validUntil)";

			var params = new Object();
			params['hash'] = hash;
			params['host'] = host;
			params['trust'] = trust;
			params['validUntil'] = validUntil;

			cbFrontend.cbdatabase.executeAsynchronous(sqlStatement, params, null);	

			// 2) Add the entry to the internal cache.
			
			// Create the new entry ...
			var newEntry = new CBTrustDecisionCacheEntry(hash, host, trust, validUntil);

			// ... and add it.
			self.addInternal(newEntry);
		};
		

		/**
		* Add a CBTrustDecisionCacheEntry to the internal cache
		* 
		* Please note: To my best knowledge there is only ONE thread that accesses the CBTrustDecisionCache (the "GUI"-thread). Nevertheless I am not 100%-sure if there is only one "GUI"-thread or if there are more than one. To reduce pot.
		* multithreading problems the operations required for the addition of a CBTrustDecisionCacheEntry are first conducted on a copy instead of on the actual cache. Doing that prevents the cache from becoming inconsistent but might lead to
		* a "lost-update" (which is not too bad since it's only a cache)
		* 
		* @param entry The entry to add to the internal cache
		*/
		CBTrustDecisionCache.prototype.addInternal = function addInternal(entry) {
			
			// Clone the original cache
			var cacheCopy = clone(self.recentlyUsedCertificatesValidities);

			// Add new entry at the front position of the copy
			cacheCopy.unshift(entry);

			// If the cache reached its maximal capacity: remove the oldest entry
			if (cacheCopy.length > self.maximumSizeOfRUCV) {
				cacheCopy.pop();
			}

			// Replace the actual cache with its modified copy (might cause a "lost update")
			self.recentlyUsedCertificatesValidities = cacheCopy;
		};
		
		/**
		 * Remove a entry stating whether or not to trust a certificate for a specific host or not from the local cache.
		 * 
		 * @param hash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param host The host that should or should not be trusted when sending a certificate with hash "hash"
		 */
		CBTrustDecisionCache.prototype.remove = function remove(hash, host) {

			/*
			 * 1) Remove the entry from the internal cache. 
			 * 
			 * Doing this is equal to adding an entry for the "hash"/"host"-combination which is not valid anymore. This entry is created here.
			 */
			var newEntry = new CBTrustDecisionCacheEntry(hash, host, false, 0);

			// Insert the new cache entry into the internal cache.
			self.addInternal(newEntry);
			
			// 2) remove from database (=persistent) cache
			var sqlStatement = "DELETE FROM certTrust WHERE CertHash = :hash AND Host = :host";

			var params = new Object();
			params['hash'] = hash;
			params['host'] = host;

			cbFrontend.cbdatabase.executeAsynchronous(sqlStatement, params, null);
			
		};
		
		/**
		 * Look for a entry stating whether or not to trust a certificate for a specific host or not in the local cache.
		 * 
		 * @param hash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param host The host that should or should not be trusted when sending a certificate with hash "hash"
		 * @returns If there is an entry for the "hash"/"host"-combination then it will be returned in its CBTrustDecisionCacheEntry-representation. If there isn't then null will be returned
		 */
		CBTrustDecisionCache.prototype.lookForMatchInInternalCache = function lookForMatchInInternalCache(hash, host) {
			
			// Iterate over all of the cache's elements
			var cacheEntry = null;
			for ( var i = 0; i < self.recentlyUsedCertificatesValidities.length; i++) {
				
				// For each element ...
				cacheEntry = self.recentlyUsedCertificatesValidities[i];
				
				// check if its "hash"/"host"-combination matches the one that is being searched for
				if (cacheEntry.hash == hash && cacheEntry.host == host) {
					// If yes: return it
					break;
					
				} else {
					// if not: go on with the search
					cacheEntry = null;
				}
			}
			return cacheEntry;
		};

		/**
		 * Check if a certificate has already been seen for a host and - if it was - if it should be trusted for the host or not.
		 * 
		 * @param hash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param host The host that should or should not be trusted when sending a certificate with hash "hash"
		 * @param checkCBServerOnly If set to "true" then only connections to the Crossbear-Server will be checked. All others will return CBTrustDecisionCacheReturnTypes.OK
		 * @returns One of the CBTrustDecisionCacheReturnTypes stating whether or not a certificate is known for a host and - in case it is - if it should be trusted or not.
		 */
		CBTrustDecisionCache.prototype.checkValidity = function checkValidity(hash, host, checkCBServerOnly) {

			// Connections to the Crossbear server MUST use the certificate that ships with the Crossbear-Firefox-plugin. ANY other certificate sent by a server that claims to be the Crossbear server MUST be rejected (Since that is most likely a Mitm's certificate)!
			if (host == cbFrontend.cbServerName) {

				// Is the certificate the one that ships with the Crossbear-Firefox-plugin?
				if (hash == self.cbServerCertHash) {
					// If yes: everything is okay!
					return CBTrustDecisionCacheReturnTypes.CB_SERVER_OK;
				} else {
					// If no: reject the certificate (and warn the user)
					return CBTrustDecisionCacheReturnTypes.CB_SERVER_NOT_VALID;
				}
			}
			
			// In case, the only connections that should be checked are the ones to the Crossbear-Server, all others will return "OK"
			if(checkCBServerOnly){
				return CBTrustDecisionCacheReturnTypes.OK;
			}

			// For connections to all other hosts: Look for the "hash"/"host"-combination in the internal cache
			var cacheEntry = this.lookForMatchInInternalCache(hash, host);


			// If the internal cache didn't contain the "hash"/"host"-combination -> look for it in the database (= persistent cache)
			if (cacheEntry == null) {

				// Build the SQL-statement ...
				var sqlStatement = "SELECT * FROM certTrust WHERE CertHash = :hash AND Host = :host LIMIT 1";
				var params = new Object();
				params['hash'] = hash;
				params['host'] = host;
				
				// ... execute it and get its result.
				var expectedRows = [ "CertHash", "Host", "Trust", "ValidUntil" ];
				var databaseCache = cbFrontend.cbdatabase.executeSynchronous(sqlStatement, params, expectedRows);

				// If the local database didn't contain the requested "hash"/"host"-combination either it is not in the cache at all. In that case a request to the CB server is necessary
				if (databaseCache.length == 0) {
					return CBTrustDecisionCacheReturnTypes.NOT_IN_CACHE;
				}

				// If it did contain a entry for the requested "hash"/"host"-combination then convert it into a CBTrustDecisionCacheEntry-object ... 
				cacheEntry = new CBTrustDecisionCacheEntry(databaseCache[0].CertHash, databaseCache[0].Host, databaseCache[0].Trust, databaseCache[0].ValidUntil);

				// ... and add it to the internal cache.
				self.addInternal(cacheEntry);

			}
			
			// Get the Timestamp for the current local time
			var currentTimestamp = Math.round(new Date().getTime() / 1000);

			// And check if the CBTrustDecisionCacheEntry that was found for the "hash"/"host"-combination is currently valid
			if (cacheEntry.validUntil > currentTimestamp) {
				
				// If it is: check what it states about whether or not to trust the certificate for "host" and return that statement.
				if (cacheEntry.trust == 1) {
					return CBTrustDecisionCacheReturnTypes.OK;
				} else {
					return CBTrustDecisionCacheReturnTypes.NOT_VALID;
				}
			} else {
				/*
				 * If the Cache entry is no longer valid: Return that finding. 
				 * 
				 * Removing it from the internal cache is not necessary: as soon as a newer entry for the "hash"/"host"-combination is added to the cache, the old one will not be found anymore.
				 * Removing it from the database cache will be done the next time Firefox is restarted.
				 */ 
				return CBTrustDecisionCacheReturnTypes.NOT_IN_CACHE;
			}

		};

	}

}