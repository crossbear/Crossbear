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

import java.net.InetAddress;
import java.security.InvalidParameterException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Date;
import java.sql.Timestamp;
import java.util.Properties;

/**
 * This class implements a comfortable wrapper for SQL-Database connections. It provides
 * - easy no-knowledge-creation of database connections
 * - easy to use PreparedStatements (all SQL-commands executed by the use of this class are executed as PreparedStatements -> Protection against SQL-Injection attacks)
 * - transactions
 * 
 * Please Note: Since Crossbear uses transactions, a new Database connection should be used every time a page is being processed!
 * 
 * @author Thomas Riedmaier
 *
 */
public class Database {
	
	/**
	 * Set the parameters of a PreparedStatement
	 * 
	 * @param ps The PreparedStatement to set the parameters for
	 * @param params The Parameters to set in the order of their occurrence in the SQL-Statement
	 * @throws SQLException
	 * @throws InvalidParameterException
	 */
	private static void setParams(PreparedStatement ps, Object[] params) throws SQLException,InvalidParameterException{
		
		// Iterate over all parameters and set them in the order in which they occur in the SQL-Statment
		for(int i =0;i<params.length;i++){
			
			// Add the parameters to the Statement. Depending on the parameter's Class-Type the PreparedStatement-API wants a different function to be used: Choose the correct one 
			if (params[i] instanceof Boolean){
				ps.setBoolean(i+1, (Boolean)params[i]);
				
			} else if (params[i] instanceof Byte){
				ps.setByte(i+1, (Byte)params[i]);
				
			} else if (params[i] instanceof byte[]){
				ps.setBytes(i+1, (byte[])params[i]);
				
			} else if (params[i] instanceof Date){
				ps.setDate(i+1, (Date)params[i]);
				
			} else if (params[i] instanceof Integer){
				ps.setInt(i+1, (Integer)params[i]);
				
			} else if (params[i] instanceof Long){
				ps.setLong(i+1, (Long)params[i]);
				
			} else if (params[i] instanceof String){
				ps.setString(i+1, (String)params[i]);
				
			} else if (params[i] instanceof Timestamp){
				ps.setTimestamp(i+1, (Timestamp)params[i]);
				
			} else if (params[i] instanceof InetAddress){
				ps.setString(i+1, ((InetAddress)params[i]).getHostAddress());
				
			} else {
				throw new InvalidParameterException("Unsupported/Unimplemented type of parameter");
			}		
		}
	}

	// The JDBC Connector Class.
	private static final String dbClassName = "org.postgresql.Driver";
	
	// The java.sql.Connection that is wrapped by this class
	private final Connection con;
	
	/**
	 * Create and open a new connection to the database using the stored login credentials
	 * 
	 * @param url The location of the Crossbear database
	 * @param user The user to access the database
	 * @param password The password for the user "user"
	 * @throws ClassNotFoundException
	 * @throws SQLException
	 */
	public Database(String url, String user, String password) throws ClassNotFoundException, SQLException{
		
		// Get the classname of the database driver
	    Class.forName(dbClassName);

	    // Set username and password
	    Properties p = new Properties();
	    p.setProperty("user",user);
	    p.setProperty("password",password);

	    // Try to connect
	    con = DriverManager.getConnection(url,p);
	    
	}
	
	/* (non-Javadoc)
	 * @see  java.sql.Connection#close()
	 */
	public void close() throws SQLException{
		con.close();
	}
	
	/* (non-Javadoc)
	 * @see  java.sql.Connection#commit()
	 */
	public void commit() throws SQLException{
		con.commit();
	}
	
	/**
	 * Execute a SQL-"INSERT"-Statement as PreparedStatment.
	 * 
	 * @param sqlstmt The statement to execute (e.g. "INSERT INTO HuntingTaskListCache (Data,ValidUntil) VALUES (?,?)")
	 * @param params The parameters for the PreparedStatement in the order in which they are used in sqlstmt
	 * @return The ID of the inserted row
	 * @throws SQLException
	 * @throws InvalidParameterException
	 */
	public String executeInsert(String sqlstmt, Object[] params) throws SQLException, InvalidParameterException {

		// Create a new PreparedStatement that will return the KEYs it generated
		PreparedStatement ps = con.prepareStatement(sqlstmt, PreparedStatement.RETURN_GENERATED_KEYS);

		// Try to set the parameters
		setParams(ps, params);

		// Execute it
		ps.executeUpdate();

		// Get the id of the inserted row and return it
		ResultSet keys = ps.getGeneratedKeys();
		keys.next();
		return keys.getString(1);

	}
	
	/**
	 * Execute a SQL-Statement as PreparedStatment.
	 * 
	 * @param sqlstmt The statement to execute (e.g. "SELECT * FROM CertCache WHERE HostPort = ? LIMIT 1")
	 * @param params The parameters for the PreparedStatement in the order in which they are used in sqlstmt
	 * @return The result that is returned by the database in response to the query
	 * @throws SQLException
	 * @throws InvalidParameterException
	 */
	public ResultSet executeQuery(String sqlstmt, Object[] params) throws SQLException,InvalidParameterException{
		
		// Create a new PreparedStatement
		PreparedStatement ps = con.prepareStatement(sqlstmt);
		
		// Try to set the parameters
		setParams(ps, params);
		
		// Execute it and return the result of the execution
		return ps.executeQuery();
		
	}
	
	/**
	 * Execute a SQL-"UPDATE"-Statement as PreparedStatment.
	 * 
	 * @param sqlstmt The statement to execute (e.g. "UPDATE CertCache SET Certificate = ?, ValidUntil = ? WHERE HostPort = ?")
	 * @param params The parameters for the PreparedStatement in the order in which they are used in sqlstmt
	 * @return The count of affected rows
	 * @throws SQLException
	 * @throws InvalidParameterException
	 */
	public int executeUpdate(String sqlstmt, Object[] params) throws SQLException,InvalidParameterException{
		
		// Create a new PreparedStatement
		PreparedStatement ps = con.prepareStatement(sqlstmt);
		
		// Try to set the parameters
		setParams(ps, params);
		
		// Execute it and return the count of affected rows
		return ps.executeUpdate();
		
	}
	
	/* (non-Javadoc)
	 * @see  java.sql.Connection#rollback()
	 */
	public void rollback() throws SQLException{
		con.rollback();
	}
	
	/* (non-Javadoc)
	 * @see  java.sql.setAutoCommit#rollback(boolean)
	 */
	public void setAutoCommit(boolean mode) throws SQLException{
		con.setAutoCommit(mode);
	}
	
}
