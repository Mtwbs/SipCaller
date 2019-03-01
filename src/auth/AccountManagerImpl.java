package auth;
import javax.sip.ClientTransaction;

import gov.nist.javax.sip.clientauthutils.AccountManager;
import gov.nist.javax.sip.clientauthutils.UserCredentials;
import auth.Shootist;

public class AccountManagerImpl implements AccountManager {
	
	private static String username="mom";
	private static String realm="open-ims.test";
	private static String password="mom";
	 public UserCredentials getCredentials(ClientTransaction challengedTransaction, String realm) {
       return new UserCredentialsImpl(username+"@"+realm,"nist.gov",password);
    }

}