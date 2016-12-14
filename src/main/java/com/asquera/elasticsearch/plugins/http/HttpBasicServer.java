package com.asquera.elasticsearch.plugins.http;

import com.asquera.elasticsearch.plugins.http.auth.Client;
import com.asquera.elasticsearch.plugins.http.auth.InetAddressWhitelist;
import com.asquera.elasticsearch.plugins.http.auth.ProxyChains;
import com.asquera.elasticsearch.plugins.http.auth.XForwardedFor;
import org.elasticsearch.common.Base64;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.jackson.dataformat.yaml.YAMLFactory;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.http.HttpServer;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.node.service.NodeService;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.net.InetSocketAddress;

import static org.elasticsearch.rest.RestStatus.OK;
import static org.elasticsearch.rest.RestStatus.UNAUTHORIZED;

// # possible http config
// http.basic.user: admin
// http.basic.password: password
// http.basic.ipwhitelist: ["localhost", "somemoreip"]
// http.basic.xforward: "X-Forwarded-For"
// # if you use javascript
// # EITHER $.ajaxSetup({ headers: { 'Authorization': "Basic " + credentials }});
// # OR use beforeSend in  $.ajax({
// http.cors.allow-headers: "X-Requested-With, Content-Type, Content-Length, Authorization"
//
/**
 * @author Florian Gilcher (florian.gilcher@asquera.de)
 * @author Peter Karich
 */
public class HttpBasicServer extends HttpServer {

    private final String adminuser;
    private final String adminpassword;
    private final InetAddressWhitelist whitelist;
    private final ProxyChains proxyChains;
    private final String xForwardHeader;
    private final boolean log;
    private final List<UserAuth> users = new ArrayList<UserAuth>();
    private final String usersFilename;


    @Inject public HttpBasicServer(Settings settings, Environment environment, HttpServerTransport transport,
            RestController restController,
            NodeService nodeService) {
        super(settings, environment, transport, restController, nodeService);

        this.adminuser = settings.get("http.basic.user", "admin");
        this.adminpassword = settings.get("http.basic.password", "admin_pw");
        final boolean whitelistEnabled = settings.getAsBoolean("http.basic.ipwhitelist", true);
        String [] whitelisted = new String[0];
        if (whitelistEnabled) {
            whitelisted = settings.getAsArray("http.basic.ipwhitelist", new String[]{"localhost", "127.0.0.1"});
        }
        this.whitelist = new InetAddressWhitelist(whitelisted);
        this.proxyChains = new ProxyChains(
            settings.getAsArray(
              "http.basic.trusted_proxy_chains", new String[]{""}));

        // for AWS load balancers it is X-Forwarded-For -> hmmh does not work
        this.xForwardHeader = settings.get("http.basic.xforward", "");
        this.log = settings.getAsBoolean("http.basic.log", true);
        
        Loggers.getLogger(getClass()).info("using {} with whitelist: {}, xforward header field: {}, trusted proxy chain: {}",
                adminuser, whitelist, xForwardHeader, proxyChains);
        this.usersFilename = environment.configFile().getAbsolutePath() + File.separator + "users.conf";
        String ret = reloadUsersFile();
        Loggers.getLogger(getClass()).info(ret);
         
    }

    @Override
    public void internalDispatchRequest(final HttpRequest request, final HttpChannel channel) {
        if (log) {
            logRequest(request);
        }

        if (authorized(request))
        {
            if (usersReload(request)) 
            { // display custom health check page when unauthorized (do not display too much server info)
            	String ret = reloadUsersFile();
            	channel.sendResponse(new BytesRestResponse(OK, "{\"OK\":{\"" + ret + "\"}}"));
            }
            else // Send to ES
            	super.internalDispatchRequest(request, channel);
        } 
        else if (healthCheck(request)) 
        { // display custom health check page when unauthorized (do not display too much server info)
            channel.sendResponse(new BytesRestResponse(OK, "{\"OK\":{}}"));
        }
        else 
        {
            logUnAuthorizedRequest(request);
            BytesRestResponse response = new BytesRestResponse(UNAUTHORIZED, "Authentication Required");
            response.addHeader("WWW-Authenticate", "Basic realm=\"Restricted\"");
            channel.sendResponse(response);
        }
    }

    // @param an http method
    // @returns True iff the method is one of the methods used for health check
    private boolean isHealthCheckMethod(final RestRequest.Method method){
        final RestRequest.Method[] healthCheckMethods = { RestRequest.Method.GET, RestRequest.Method.HEAD };
        return Arrays.asList(healthCheckMethods).contains(method);
    }

    // @param an http Request
    // @returns True iff we check the root path and is a method allowed for healthCheck
    private boolean healthCheck(final HttpRequest request) {
        return request.path().equals("/") && isHealthCheckMethod(request.method());
    }

    // @param an http Request
    // @returns True iff we check the root path and is a method allowed for healthCheck
    private boolean usersReload(final HttpRequest request) {
    	//Loggers.getLogger(getClass()).info("LOG CHEGOU path={} method={}",request.path(), request.method());
        return request.path().equals("/_usersreload") && request.method().equals(RestRequest.Method.GET);
    }
    

  /**
   *
   *
   * @param request
   * @return true if the request is authorized
   */
    private boolean authorized(final HttpRequest request) {
      return allowOptionsForCORS(request) || authBasic(request) || ipAuthorized(request);
    }

  /**
   *
   *
   * @param request
   * @return true iff the client is authorized by ip
   */
    private boolean ipAuthorized(final HttpRequest request) {
      boolean ipAuthorized = false;
      String xForwardedFor = request.header(xForwardHeader);
      Client client = new Client(getAddress(request),
                            whitelist,
                            new XForwardedFor(xForwardedFor),
                            proxyChains);
      ipAuthorized = client.isAuthorized();
      if (ipAuthorized) {
        if (log) {
          String template = "Ip Authorized client: {}";
          Loggers.getLogger(getClass()).info(template, client);
        }
      } else {
        String template = "Ip Unauthorized client: {}";
        Loggers.getLogger(getClass()).error(template, client);
      }
      return ipAuthorized;
    }

    public String getDecoded(HttpRequest request) {
        String authHeader = request.header("Authorization");
        if (authHeader == null)
            return "";

        String[] split = authHeader.split(" ", 2);
        if (split.length != 2 || !split[0].equals("Basic"))
            return "";
        try {
            return new String(Base64.decode(split[1]));
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private boolean authBasic(final HttpRequest request) {
        String decoded = "";
        try 
        {
            decoded = getDecoded(request);
            if (!decoded.isEmpty()) 
            {
                String[] userAndPassword = decoded.split(":", 2);
                String givenUser = userAndPassword[0];
                String givenPass = userAndPassword[1];
                
                // Validates Admin user
                if (this.adminuser.equals(givenUser) && this.adminpassword.equals(givenPass))
                    return true;
                
                // Validates All other users
                for(int i = 0; i < this.users.size(); i++)
                {
                	if(this.users.get(i).user.equals(givenUser) && this.users.get(i).pass.equals(givenPass))
                	{
                		return true;

                		//TODO: Implementar depois validação por método e index
                		//if(request.path().equals("/") && isHealthCheckMethod(request.method());
                		//break;
                	}
                }
            }
        } catch (Exception e) {
            logger.warn("Retrieving of user and password failed for " + decoded + " ," + e.getMessage());
        }
        return false;
    }


  /**
   *
   *
   * @param request
   * @return the IP adress of the direct client
   */
    private InetAddress getAddress(HttpRequest request) {
        return ((InetSocketAddress) request.getRemoteAddress()).getAddress();
    }


    /**
     * https://en.wikipedia.org/wiki/Cross-origin_resource_sharing the
     * specification mandates that browsers “preflight” the request, soliciting
     * supported methods from the server with an HTTP OPTIONS request
     */
    private boolean allowOptionsForCORS(HttpRequest request) {
        // in elasticsearch.yml set
        // http.cors.allow-headers: "X-Requested-With, Content-Type, Content-Length, Authorization"
        if (request.method() == Method.OPTIONS) {
//            Loggers.getLogger(getClass()).error("CORS type {}, address {}, path {}, request {}, content {}",
//                    request.method(), getAddress(request), request.path(), request.params(), request.content().toUtf8());
            return true;
        }
        return false;
    }

    public void logRequest(final HttpRequest request) {
      String addr = getAddress(request).getHostAddress();
      String t = "Authorization:{}, type: {}, Host:{}, Path:{}, {}:{}, Request-IP:{}, " +
        "Client-IP:{}, X-Client-IP{}";
      logger.info(t,
                  request.header("Authorization"),
                  request.method(),
                  request.header("Host"),
                  request.path(),
                  xForwardHeader,
                  request.header(xForwardHeader),
                  addr,
                  request.header("X-Client-IP"),
                  request.header("Client-IP"));
    }

    public void logUnAuthorizedRequest(final HttpRequest request) {
        String addr = getAddress(request).getHostAddress();
        String t = "UNAUTHORIZED type:{}, address:{}, path:{}, request:{},"
          + "content:{}, credentials:{}";
        Loggers.getLogger(getClass()).error(t,
                request.method(), addr, request.path(), request.params(),
                request.content().toUtf8(), getDecoded(request));
    }
    
    public String reloadUsersFile()
    {
    	String filename = usersFilename;
    	String result = "";
    	
    	Loggers.getLogger(getClass()).info("Loading users file. Use GET /_usersreload to reload: {}", filename);
    	
    	// Permissions File
    	BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(filename));
		} 
		catch (FileNotFoundException e) 
		{
			// TODO Auto-generated catch block
			//e.printStackTrace();
			Loggers.getLogger(getClass()).error("USERS FILE NOT FOUND: {}", filename);
		}
		
		if(br != null)
		{
	    	try 
	    	{
	    	    String line = br.readLine();
	    	    while (line != null) 
	    	    {
	    	    	String[] lineSplit = line.split(":");
	    	    	if(lineSplit.length == 4)
	    	    	{
	    	    		users.add(new UserAuth(lineSplit[0], lineSplit[1], lineSplit[2], lineSplit[3]));
	    	    		if(result.isEmpty())
	    	    			result += lineSplit[0];
	    	    		else
	    	    			result += ", " + lineSplit[0];
	    	    	}
	    	        line = br.readLine();
	    	    }
	    	} 
	    	catch (IOException e) 
	    	{
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
	    	finally 
	    	{
	    	    try 
	    	    {
					br.close();
				} 
	    	    catch (IOException e) 
	    	    {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	    	}
		}
		
		return "Loaded users: " + result;
    }

}
