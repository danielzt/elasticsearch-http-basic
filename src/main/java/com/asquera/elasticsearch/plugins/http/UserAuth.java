package com.asquera.elasticsearch.plugins.http;

public class UserAuth {
	public UserAuth(String _user, String _pass, String _permissions, String _indexes) 
	{
		// TODO Auto-generated constructor stub
		user = _user;
		pass = _pass;
		permissions = _permissions;
		indexes = _indexes;
	}
	public String user;
	public String pass;
	public String permissions;
	public String indexes;
}
