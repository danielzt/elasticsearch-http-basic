package com.asquera.elasticsearch.plugins.http;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.tools.ant.filters.TokenFilter.Trim;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.rest.RestRequest;

public class UserAuth {
	public UserAuth(String _user, String _ip, String _pass, String _methods, String _indexes, boolean _isAdmin) 
	{
		// TODO Auto-generated constructor stub
		user = _user;
		ip = _ip;
		pass = _pass;
		methods = _methods.toUpperCase().trim();
		indexes = _indexes.trim();
		isAdmin = _isAdmin;
		
		listMethods = Arrays.asList(methods.split(","));
		listIndexes = Arrays.asList(indexes.split(","));

	}
	
	public String user;
	public String ip;
	public String pass;
	public String methods;
	private List<String> listMethods;
	private List<String> listIndexes;
	public String indexes;
	public boolean isAdmin;
	public boolean hasPermission(final HttpRequest request)
	{
		if(methods.equals("*") || listMethods.contains(request.method().toString()))
		{
			// Método OK, lets validate Indexes
			if(indexes.equals("*"))
				return true;

			//Loggers.getLogger(getClass()).error("PATH: ", request.path());
			
			String index = "";
			String[] pathArr = request.path().split("/");
			if(pathArr.length > 1)
				index = pathArr[1];
			else if(pathArr.length > 0)
				index = pathArr[0];
			
			if(listIndexes.contains(index)) // Method and Indexes ok, grant access.
				return true;
		}
		return false;
	}
}
