package auth;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.SimpleLayout;

import gov.nist.javax.sip.SipStackExt;
import gov.nist.javax.sip.clientauthutils.AuthenticationHelper;
import gov.nist.javax.sip.clientauthutils.DigestServerAuthenticationHelper;
import gov.nist.javax.sip.header.HeaderFactoryImpl;
import gov.nist.javax.sip.header.ims.*;
import junit.framework.TestCase;
import javax.sip.*;
import javax.sip.address.*;
import javax.sip.header.*;
import javax.sip.message.*;


import java.util.*;



import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.test.BindingLifetimeTest;
import de.javawi.jstun.util.UtilityException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.*;

/**
 * <p>This class is a UAS template.</p>
 * <p>Exemplifies the creation and parsing of the SIP P-Headers for IMS</p>
 *
 * <p>based on examples.simplecallsetup, by M. Ranganathan</p>
 * <p>issued by Miguel Freitas (IT) PT-Inovacao</p>
 */

public class Shootist implements SipListener {
	static String transport = "udp";

	private Hashtable serverTxTable = new Hashtable();
	
	private static String unexpectedException = "Unexpected exception ";
	
    private static AddressFactory addressFactory;

    private static MessageFactory messageFactory;

    private static HeaderFactory headerFactory;

    private static SipStack sipStack;
/*
    private static final String myAddress = "127.0.0.1";

    private static final int myPort = 5070;
*/
 //   protected ServerTransaction inviteTid;

    private Response okResponse;

    private Request inviteRequest;

    private static Dialog dialog;
    
    private static Dialog dialogcall;

    public static final boolean callerSendsBye = true;
    
    private static ContactHeader contactHeader;
    
    private static ClientTransaction inviteTidd;
    
    private static Request request;
    
    private static SipProvider sipProvider;
    
    private static ListeningPoint udpListeningPoint;
    
    public static String user="mom";
    
    public static String invite_receive="calleelv";
 
    String peerHostPort = "163.17.21.188:5060";
    
    long invco = 1;

    private static long cseq = 0L;
    
    private static Header contactH;
    
    public static String ListeningPoint;
    
    static Object stun;
    
    static int port;
    private static Logger logger = Logger.getLogger(Shootist.class);
	

    protected static final String usageString = "java "
            + "examples.shootist.Shootist \n"
            + ">>>> is your class path set to the root?";

    private static void usage() {
        System.out.println(usageString);
        junit.framework.TestCase.fail("Exit JVM");

    }

    public void processRequest(RequestEvent requestReceivedEvent) {
        Request request = requestReceivedEvent.getRequest();
        ServerTransaction serverTransactionId = requestReceivedEvent
                .getServerTransaction();

        System.out.println("\n\nRequest " + request.getMethod()
                + " received at " + sipStack.getStackName()
                + " with server transaction id " + serverTransactionId);

     

    }

    public void processResponse(ResponseEvent responseEvent) {
    	
            System.out.println("Got a response");
       
            Response response = (Response) responseEvent.getResponse();
            
            ClientTransaction tid = responseEvent.getClientTransaction();
            CSeqHeader cseq = (CSeqHeader) response.getHeader(CSeqHeader.NAME);

            System.out.println("Response received : Status Code = "
                    + response.getStatusCode() + " " + cseq);
            if (tid == null)
            {
              System.out.println("Stray response -- dropping ");
              return;
            }
            
            /*
            System.out.println("transaction state is " + tid.getState());
            System.out.println("Dialog = " + tid.getDialog());
            System.out.println("Dialog State is " + tid.getDialog().getState());
            */
            try {
                if (response.getStatusCode() == Response.OK) {
                    if (cseq.getMethod().equals(Request.REGISTER)) {
                    	System.out.println("Sending ACK "+user+"!!!!!! REGISTER OK");
/*
                    	Dialog dialog = inviteTidd.getDialog();
                        Request ackRequest = dialog.createAck( cseq.getSeqNumber() );      
                        System.out.println("Sending ACK");
                        dialog.sendAck(ackRequest); */
                    }else if (response.getStatusCode() == Response.OK &&
                        		cseq.getMethod().equals(Request.INVITE)) {
                        	
                            processInviteOK(response, tid);
                    } else if (cseq.getMethod().equals(Request.CANCEL)) {
                        if (dialogcall.getState() == DialogState.CONFIRMED) {
                            // oops cancel went in too late. Need to hang up the
                            // dialog.
                            System.out
                                    .println("Sending BYE -- cancel went in too late !!");
                            Request byeRequest = dialogcall.createRequest(Request.BYE);
                            ClientTransaction ct = sipProvider
                                    .getNewClientTransaction(byeRequest);
                            dialogcall.sendRequest(ct);
                        }
                    }
                } else if (response.getStatusCode() == Response.UNAUTHORIZED) {  
                	/*
                		AuthenticationHelper authenticationHelper = 
                             ((SipStackExt) sipStack).getAuthenticationHelper(new AccountManagerImpl(), headerFactory);
                         
                        inviteTidd = authenticationHelper.handleChallenge(response, tid, sipProvider, 5);
                       
                        inviteTidd.sendRequest();
                      
                        invco++;      
                        */
                	register(response);
                }
       
            } catch (Exception ex) {
                ex.printStackTrace();
                System.exit(0);
            }

        }
    
    
    public void register(Response response)
    {
      try
      {
        String transport = "udp";
        
        ArrayList viaHeaders = new ArrayList();
        
        ViaHeader viaHeader = headerFactory.createViaHeader(stun.toString(), 
          port, 
          transport, null);
        

        viaHeaders.add(viaHeader);
        


        MaxForwardsHeader maxForwardsHeader = headerFactory.createMaxForwardsHeader(70);
        


        CallIdHeader callIdHeader = (CallIdHeader)response.getHeader("call-id");
        


        cseq += 1L;
        CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(cseq, "REGISTER");
        
        javax.sip.address.Address fromAddress = addressFactory.createAddress("sip:" + user + "@open-ims.test");
        
        FromHeader fromHeader = headerFactory.createFromHeader(fromAddress, "12345");
        


        ToHeader toHeader = headerFactory.createToHeader(fromAddress, null);
        






        MaxForwardsHeader maxForwards = headerFactory
          .createMaxForwardsHeader(70);
        URI requestURI = addressFactory.createURI("sip:open-ims.test");
        Request request = messageFactory.createRequest(requestURI, 
          "REGISTER", callIdHeader, cSeqHeader, fromHeader, 
          toHeader, viaHeaders, maxForwards);
        
        request.addHeader(callIdHeader);
        
        request.addHeader(cSeqHeader);
        
        request.addHeader(fromHeader);
        
        request.addHeader(toHeader);
        
        request.addHeader(maxForwardsHeader);
        
        request.addHeader(viaHeader);
        


        request.addHeader(contactH);
        
        
        if (response != null)
        {
          AuthorizationHeader authHeader = makeAuthHeader(response, request);
          
          request.addHeader(authHeader);
        }
        javax.sip.address.Address fromNameAddress = addressFactory.createAddress(fromAddress.toString());
        

        HeaderFactoryImpl headerFactoryImpl = new HeaderFactoryImpl();
        

        AllowHeader allow1 = 
          headerFactory.createAllowHeader("REGISTER");
        request.addHeader(allow1);
        AllowHeader allow2 = 
          headerFactory.createAllowHeader("PRACK");
        request.addHeader(allow2);
        AllowHeader allow3 = 
          headerFactory.createAllowHeader("UPDATE");
        request.addHeader(allow3);
        
        SupportedHeader supported1 = 
          headerFactory.createSupportedHeader("100rel");
        request.addHeader(supported1);
        SupportedHeader supported2 = 
          headerFactory.createSupportedHeader("preconditions");
        request.addHeader(supported2);
        SupportedHeader supported3 = 
          headerFactory.createSupportedHeader("path");
        request.addHeader(supported3);
        
        RequireHeader require1 = 
          headerFactory.createRequireHeader("sec-agree");
        request.addHeader(require1);
        RequireHeader require2 = 
          headerFactory.createRequireHeader("preconditions");
        request.addHeader(require2);
        
        SecurityClientHeader secClient = 
          headerFactoryImpl.createSecurityClientHeader();
        secClient.setSecurityMechanism("ipsec-3gpp");
        secClient.setAlgorithm("hmac-md5-96");
        secClient.setEncryptionAlgorithm("des-cbc");
        secClient.setSPIClient(10000);
        secClient.setSPIServer(10001);
        secClient.setPortClient(5063);
        secClient.setPortServer(4166);
        request.addHeader(secClient);
        
        PAccessNetworkInfoHeader accessInfo = 
          headerFactoryImpl.createPAccessNetworkInfoHeader();
        accessInfo.setAccessType("3GPP-UTRAN-TDD");
        accessInfo.setUtranCellID3GPP("0123456789ABCDEF");
        request.addHeader(accessInfo);
        
        PrivacyHeader privacy = headerFactoryImpl.createPrivacyHeader("header");
        request.addHeader(privacy);
        PrivacyHeader privacy2 = headerFactoryImpl.createPrivacyHeader("user");
        request.addHeader(privacy2);
        

        PPreferredIdentityHeader preferredID = 
          headerFactoryImpl.createPPreferredIdentityHeader(fromNameAddress);
        request.addHeader(preferredID);
        





        inviteTidd = sipProvider.getNewClientTransaction(request);
        


        inviteTidd.sendRequest();
        
        dialog = inviteTidd.getDialog();
      }
      catch (Exception e)
      {
        e.printStackTrace();
      }
    }
    
    
    /**
     * Process the invite request.
     */
    
    public void processInviteOK(Response ok, ClientTransaction ct)
    {
    	
        
        HeaderFactoryImpl headerFactoryImpl =
            (HeaderFactoryImpl) headerFactory;

        try
        {

            RequireHeader require = null;
            String requireOptionTags = new String();
            ListIterator li = ok.getHeaders(RequireHeader.NAME);
            
            System.out.println(RequireHeader.NAME+"zzzzzzzzzzzzzz");
            if (li != null) {
                try {
                    while(li.hasNext())
                    {
                        require = (RequireHeader) li.next();
                        requireOptionTags = requireOptionTags
                            .concat( require.getOptionTag())
                            .concat(" ");
                        
                        System.out.println("XXXXXXXXXXXXXXX111111X" );
                    }
                }
                catch (Exception ex)
                {
                    System.out.println("\n(!) Exception getting Require header! - " + ex);
                }
            }


            // this is only to illustrate the usage of this headers
            // send Security-Verify (based on Security-Server) if Require: sec-agree
            SecurityVerifyList secVerifyList = null;
            
            
            System.out.println(secVerifyList+"GGGGGG");
            System.out.println(secVerifyList.isEmpty()+"GGGGGGAAAAA");
            
            if (requireOptionTags.indexOf("sec-agree") != -1)
            {
                ListIterator secServerReceived =
                    ok.getHeaders(SecurityServerHeader.NAME);
                if (secServerReceived != null && secServerReceived.hasNext())
                {
                	System.out.println("XXXXXXXXXXXXXXXX22222" );
                	
                    System.out.println(".: Security-Server received: ");

                     while (secServerReceived.hasNext())
                    {
                        SecurityServerHeader security = null;
                        try {
                            security = (SecurityServerHeader) secServerReceived.next();
                            System.out.println("XXXXXXXXXXXXXXXX333333" );
                        }
                        catch (Exception ex)
                        {
                            System.out.println("(!) Exception getting Security-Server header : " + ex);
                        }

                        try {
                            Iterator parameters = security.getParameterNames();
                            SecurityVerifyHeader newSecVerify = headerFactoryImpl.createSecurityVerifyHeader();
                            newSecVerify.setSecurityMechanism(security.getSecurityMechanism());
                            while (parameters.hasNext())
                            {
                                String paramName = (String)parameters.next();
                                newSecVerify.setParameter(paramName,security.getParameter(paramName));
                            }

                            System.out.println("   - " + security.toString());

                        }
                        catch (Exception ex)
                        {
                            System.out.println("(!) Exception setting the security agreement!" + ex);
                            ex.getStackTrace();
                        }

                    }
                }
                System.out.println(".: Security-Verify built and added to response...");
            }

                      
            CSeqHeader cseq = (CSeqHeader) ok.getHeader(CSeqHeader.NAME);
            Request ackRequest = dialogcall.createAck( cseq.getSeqNumber() );
            
            
           
            System.out.println(dialogcall.createAck( cseq.getSeqNumber() )+"XXXXXXXXXXXXXXXXXX1");
            System.out.println((CSeqHeader) ok.getHeader(CSeqHeader.NAME)+"XAAAAAAXXXXXXXXXXXXXXXXXX1");
            if (secVerifyList != null && !secVerifyList.isEmpty())
            {
                RequireHeader requireSecAgree = headerFactory.createRequireHeader("sec-agree");
                ackRequest.setHeader(requireSecAgree);

                ackRequest.setHeader(secVerifyList);
            }

            System.out.println("Sending ACK");
            dialogcall.sendAck(ackRequest);
            System.out.println("XXXXXXXXXXXXXXXX" );
        }
        catch (Exception ex)
        {
            System.out.println("(!) Exception sending ACK to 200 OK " +
                    "response to INVITE : " + ex);
        }
    }
    
    
    /**
     * Process the invite request.
     */
   

    /**
     * Process the invite request.
     */
   
    
    
    
   
    public void processTimeout(javax.sip.TimeoutEvent timeoutEvent) {
        Transaction transaction;
        if (timeoutEvent.isServerTransaction()) {
            transaction = timeoutEvent.getServerTransaction();
        } else {
            transaction = timeoutEvent.getClientTransaction();
        }
        System.out.println("state = " + transaction.getState());
        System.out.println("dialog = " + transaction.getDialog());
        System.out.println("dialogState = "
                + transaction.getDialog().getState());
        System.out.println("Transaction Time out");
    }

  


    public  void init() {
        SipFactory sipFactory = null;
        sipStack = null;
        sipFactory = SipFactory.getInstance();
        sipFactory.setPathName("gov.nist");
        Properties properties = new Properties();
        // If you want to try TCP transport change the following to 
     
        properties.setProperty("javax.sip.OUTBOUND_PROXY", peerHostPort + "/"
                + transport);
        // If you want to use UDP then uncomment this.
        properties.setProperty("javax.sip.STACK_NAME", "shootist");

        // The following properties are specific to nist-sip
        // and are not necessarily part of any other jain-sip
        // implementation.撅亥��
        // You can set a max message size for tcp transport to
        // guard against denial of service attack.
        properties.setProperty("gov.nist.javax.sip.DEBUG_LOG",
                "shootistdebug.txt");
        properties.setProperty("gov.nist.javax.sip.SERVER_LOG",
                "shootistlog.txt");

        // Drop the client connection after we are done with the transaction.
        properties.setProperty("gov.nist.javax.sip.CACHE_CLIENT_CONNECTIONS",
                "false");
        // Set to 0 (or NONE) in your production code for max speed.
        // You need 16 (or TRACE) for logging traces. 32 (or DEBUG) for debug + traces.
        // Your code will limp at 32 but it is best for debugging.
        properties.setProperty("gov.nist.javax.sip.TRACE_LEVEL", "TRACE");

        try {  
            // Create SipStack object
            sipStack = sipFactory.createSipStack(properties);
            System.out.println("createSipStack " + sipStack);
        } catch (PeerUnavailableException e) {
            // could not find
            // gov.nist.jain.protocol.ip.sip.SipStackImpl
            // in the classpath
            e.printStackTrace();
            System.err.println(e.getMessage());
            System.exit(0);
        }

        try {
            headerFactory = sipFactory.createHeaderFactory();
            addressFactory = sipFactory.createAddressFactory();
            messageFactory = sipFactory.createMessageFactory();
            udpListeningPoint = sipStack.createListeningPoint(ListeningPoint,
                    6020, "udp");
            sipProvider = sipStack.createSipProvider(udpListeningPoint);
            Shootist listener = this;
            sipProvider.addSipListener(listener);
           
            String fromName = user;
            String fromSipAddress = "open-ims.test";  
            String toUser = user;
            String toSipAddress = "open-ims.test";
            
                                  
            // create >From Header
            SipURI fromAddress = addressFactory.createSipURI(fromName,
                    fromSipAddress);

            Address fromNameAddress = addressFactory.createAddress(fromAddress);
            
            FromHeader fromHeader = headerFactory.createFromHeader(
                    fromNameAddress, "12345");

            // create To Header
            SipURI toAddress = addressFactory
                    .createSipURI(toUser, toSipAddress);
            Address toNameAddress = addressFactory.createAddress(toAddress);
                       ToHeader toHeader = headerFactory.createToHeader(toNameAddress,
                    null);

            // create Request URI
            SipURI requestURI = addressFactory.createSipURI(toUser,
            		toSipAddress);

            // Create ViaHeaders

            ArrayList viaHeaders = new ArrayList();
            ViaHeader viaHeader = headerFactory.createViaHeader(stun.toString(),
                    port,
                    transport, null);
       
          
            // add via headers
            viaHeaders.add(viaHeader);

           // Create ContentTypeHeader
            ContentTypeHeader contentTypeHeader = headerFactory
                    .createContentTypeHeader("application", "sdp");

            // Create a new CallId header
            CallIdHeader callIdHeader = sipProvider.getNewCallId();

            // Create a new Cseq header
            CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(invco,
                    Request.REGISTER);

            // Create a new MaxForwardsHeader
            MaxForwardsHeader maxForwards = headerFactory
                    .createMaxForwardsHeader(70);
        
			// Create the request.
            
            Request request = messageFactory.createRequest(requestURI,
                    Request.REGISTER, callIdHeader, cSeqHeader, fromHeader,
                    toHeader, viaHeaders, maxForwards);
            this.request = request;
            
         /*   
            //Create router headers
            Address routeaddress = addressFactory.createAddress("sip:orig@scscf.open-ims.test:5060;lr");
            RouteHeader routeHeader = this.headerFactory.createRouteHeader(routeaddress);
			request.addHeader(routeHeader);
			
		*/	
         /*   // Create contact headers
            String host = address.toString();
            SipURI contactUrl = addressFactory.createSipURI(fromName, host);
            contactUrl.setPort(udpListeningPoint.getPort());
            contactUrl.setLrParam();
         */
            // Create contact headers
			String host = stun.toString();
		      contactH = headerFactory.createHeader("Contact", "<sip:" +user+"@"+stun.toString()+":"+port+ ";transport=udp>;expires=60;+g.oma.sip-im;language=\"en,fr\";+g.3gpp.smsip;+g.oma.sip-im.large-message;audio;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-vs\";+g.3gpp.cs-voice");

                      //  contactH = headerFactory.createHeader("Contact","<sip:"+user+"@"+stun.toString()+":"+port+";transport=udp>;expires=60;+g.oma.sip-im;language=\"en,fr\";+g.3gpp.smsip;+g.oma.sip-im.large-message");
                        request.addHeader(contactH);
            // Create the contact name address.
            SipURI contactURI = addressFactory.createSipURI(fromName, host);
            contactURI.setPort(sipProvider.getListeningPoint(transport)
                    .getPort());

            Address contactAddress = addressFactory.createAddress(contactURI);
                  
            // Add the contact address.瘛餃�蝜思犖�����
            contactAddress.setDisplayName(fromName);

            contactHeader = headerFactory.createContactHeader(contactAddress);
            request.addHeader(contactHeader);
        
           
            // You can add extension headers of your own making
            // to the outgoing SIP request.
            // Add the extension header.
            Header extensionHeader = headerFactory.createHeader("My-Header",
                    "my header value");
            request.addHeader(extensionHeader);

            
            
            /* ++++++++++++++++++++++++++++++++++++++++++++
             *                IMS headers
             * ++++++++++++++++++++++++++++++++++++++++++++
             */

            
            // work-around for IMS headers
            
            HeaderFactoryImpl headerFactoryImpl = new HeaderFactoryImpl();

            // Allow header
            /*
            AllowHeader allowHeader =
                headerFactory.createAllowHeader(Request.INVITE + "," +
                        Request.PRACK + "," +
                        Request.UPDATE);
            request.addHeader(allowHeader);
            */
                AllowHeader allow1 =
                headerFactory.createAllowHeader(Request.REGISTER);
            request.addHeader(allow1);
            AllowHeader allow2 =
                headerFactory.createAllowHeader(Request.PRACK);
            request.addHeader(allow2);
            AllowHeader allow3 =
                headerFactory.createAllowHeader(Request.UPDATE);
            request.addHeader(allow3);
            AllowHeader allow4 = 
                    headerFactory.createAllowHeader(Request.REGISTER);
                  request.addHeader(allow4);
           AllowHeader allow5 = 
                    headerFactory.createAllowHeader(Request.INVITE);
                  request.addHeader(allow5);

            // Supported����
            /*
            SupportedHeader supportedHeader =
                headerFactory.createSupportedHeader("100rel" + "," +
                        "precondition");
            request.addHeader(supportedHeader);
            */
            SupportedHeader supported1 =
            	headerFactory.createSupportedHeader("100rel");
            request.addHeader(supported1);
            SupportedHeader supported2 =
                headerFactory.createSupportedHeader("preconditions");
            request.addHeader(supported2);
            SupportedHeader supported3 =
                headerFactory.createSupportedHeader("path");
            request.addHeader(supported3);



            // Require
            /*
            RequireHeader requireHeader =
                headerFactory.createRequireHeader("sec-agree"+ "," +
                "precondition");
            request.addHeader(requireHeader);
            */
            RequireHeader require1 =
                headerFactory.createRequireHeader("sec-agree");
            request.addHeader(require1);
            RequireHeader require2 =
                headerFactory.createRequireHeader("preconditions");
            request.addHeader(require2);


            // Security-Client
            SecurityClientHeader secClient =
                headerFactoryImpl.createSecurityClientHeader();
            secClient.setSecurityMechanism("ipsec-3gpp");
            secClient.setAlgorithm("hmac-md5-96");
            secClient.setEncryptionAlgorithm("des-cbc");
            secClient.setSPIClient(10000);
            secClient.setSPIServer(10001);
            secClient.setPortClient(5063);
            secClient.setPortServer(4166);
            //request.addHeader(secClient);

            
            // P-Access-Network-Info P
            PAccessNetworkInfoHeader accessInfo =
                headerFactoryImpl.createPAccessNetworkInfoHeader();
            accessInfo.setAccessType("3GPP-UTRAN-TDD");
            accessInfo.setUtranCellID3GPP("0123456789ABCDEF");
            request.addHeader(accessInfo);

            // Privacy
            PrivacyHeader privacy = headerFactoryImpl.createPrivacyHeader("header");
            request.addHeader(privacy);
            PrivacyHeader privacy2 = headerFactoryImpl.createPrivacyHeader("user");
            request.addHeader(privacy2);

            // P-Preferred-Identity
            PPreferredIdentityHeader preferredID =
                headerFactoryImpl.createPPreferredIdentityHeader(fromNameAddress);
            request.addHeader(preferredID);



            /*
             * TEST
             */
            // this is only to illustrate the usage of this headers


            // P-Called-Party-ID
            // only to test
            PCalledPartyIDHeader calledPartyID =
                headerFactoryImpl.createPCalledPartyIDHeader(toNameAddress);
            request.addHeader(calledPartyID);
/*
            // P-Visited-Network-ID
            PVisitedNetworkIDHeader visitedNetworkID1 =
                headerFactoryImpl.createPVisitedNetworkIDHeader();
            visitedNetworkID1.setVisitedNetworkID(fromSipAddress
                    .substring(fromSipAddress.indexOf("@")+1));
            PVisitedNetworkIDHeader visitedNetworkID2 =
                headerFactoryImpl.createPVisitedNetworkIDHeader();
            visitedNetworkID2.setVisitedNetworkID(toSipAddress
                    .substring(toSipAddress.indexOf("@")+1));
            request.addHeader(visitedNetworkID1);
            request.addHeader(visitedNetworkID2);
*/

            // P-Associated-URI
            PAssociatedURIHeader associatedURI1 =
                headerFactoryImpl.createPAssociatedURIHeader(toNameAddress);
            PAssociatedURIHeader associatedURI2 =
                headerFactoryImpl.createPAssociatedURIHeader(fromNameAddress);
            request.addHeader(associatedURI1);
            request.addHeader(associatedURI2);


            // P-Asserted-Identity
            PAssertedIdentityHeader assertedID =
                headerFactoryImpl.createPAssertedIdentityHeader(
                        addressFactory.createAddress(toAddress));
            request.addHeader(assertedID);

            TelURL tel = addressFactory.createTelURL("+1-201-555-0123");
            Address telAddress = addressFactory.createAddress(tel);
            
            PAssertedIdentityHeader assertedID2 =
                headerFactoryImpl.createPAssertedIdentityHeader(telAddress);
            request.addHeader(assertedID2);


            // P-Charging-Function-Addresses
            PChargingFunctionAddressesHeader chargAddr =
                headerFactoryImpl.createPChargingFunctionAddressesHeader();
            chargAddr.addChargingCollectionFunctionAddress("test1.ims.test");
            chargAddr.addEventChargingFunctionAddress("testevent");
            request.addHeader(chargAddr);

            // P-Charging-Vector
            PChargingVectorHeader chargVect =
                headerFactoryImpl.createChargingVectorHeader("icid");
            chargVect.setICIDGeneratedAt("icidhost");
            chargVect.setOriginatingIOI("origIOI");
            chargVect.setTerminatingIOI("termIOI");
            request.addHeader(chargVect);

            // P-Media-Authorization
            PMediaAuthorizationHeader mediaAuth1 =
                headerFactoryImpl.createPMediaAuthorizationHeader("13579bdf");
            PMediaAuthorizationHeader mediaAuth2 =
                headerFactoryImpl.createPMediaAuthorizationHeader("02468ace");
            
            request.addHeader(mediaAuth1);
            request.addHeader(mediaAuth2);
            

            // Path header
            PathHeader path1 =
                headerFactoryImpl.createPathHeader(fromNameAddress);
            PathHeader path2 =
                headerFactoryImpl.createPathHeader(toNameAddress);
            request.addHeader(path1);
            request.addHeader(path2);
/*
            String sdpData = "v=0\r\n"
                    + "o=4855 13760799956958020 13760799956958020"
                    + " IN IP4  129.6.55.78\r\n" + "s=mysession session\r\n"
                    + "p=+46 8 52018010\r\n" + "c=IN IP4  129.6.55.78\r\n"
                    + "t=0 0\r\n" + "m=audio 6022 RTP/AVP 0 4 18\r\n"

                    // bandwith
                    + "b=AS:25.4\r\n"
                    // precondition mechanism
                    + "a=curr:qos local none\r\n"
                    + "a=curr:qos remote none\r\n"
                    + "a=des:qos mandatory local sendrec\r\n"
                    + "a=des:qos none remote sendrec\r\n"


                    + "a=rtpmap:0 PCMU/8000\r\n" + "a=rtpmap:4 G723/8000\r\n"
                    + "a=rtpmap:18 G729A/8000\r\n" + "a=ptime:20\r\n";
            byte[] contents = sdpData.getBytes();

            request.setContent(contents, contentTypeHeader);
            // You can add as many extension headers as you
            // want.
  */          
            extensionHeader = headerFactory.createHeader("My-Other-Header",
                    "my new header value ");
            request.addHeader(extensionHeader);

            Header callInfoHeader = headerFactory.createHeader("Call-Info",
                    "<http://www.antd.nist.gov>");
            request.addHeader(callInfoHeader);

          
            // Create the client transaction.
            inviteTidd = sipProvider.getNewClientTransaction(request);       
            // send the request out.
            inviteTidd.sendRequest();
          
            dialog = inviteTidd.getDialog();

        } catch (Exception ex) {	
            ex.printStackTrace();
            usage();
        }
    }
    
	  AuthorizationHeader makeAuthHeader(Response resp, Request req)
	  {
	    AuthorizationHeader nothing = null;
	    try
	    {
	      WWWAuthenticateHeader ah_c = 
	        (WWWAuthenticateHeader)resp.getHeader("WWW-Authenticate");
	      

	      AuthorizationHeader ah_r = 
	        headerFactory.createAuthorizationHeader(ah_c.getScheme());
	      

	      URI request_uri = req.getRequestURI();
	      String request_method = req.getMethod();
	      String nonce = ah_c.getNonce();
	      String algrm = ah_c.getAlgorithm();
	      String realm = ah_c.getRealm();
	      String username = user + "@open-ims.test";
	      String password = user;
	      
	      MessageDigest mdigest = MessageDigest.getInstance(algrm);
	      
	      DigestServerAuthenticationHelper Str = null;
	      
	      String A1 = username + ":" + realm + ":" + password;
	      String HA1 = DigestServerAuthenticationHelper.toHexString(mdigest.digest(A1.getBytes()));
	      

	      String A2 = request_method.toUpperCase() + ":" + request_uri;
	      String HA2 = DigestServerAuthenticationHelper.toHexString(mdigest.digest(A2.getBytes()));
	      

	      String KD = HA1 + ":" + nonce + ":" + HA2;
	      String response = DigestServerAuthenticationHelper.toHexString(mdigest.digest(KD.getBytes()));
	      
	      ah_r.setRealm(realm);
	      ah_r.setNonce(nonce);
	      ah_r.setUsername(username);
	      ah_r.setURI(request_uri);
	      ah_r.setAlgorithm(algrm);
	      ah_r.setResponse(response);
	      
	      return ah_r;
	    }
	    catch (Exception e)
	    {
	      System.out.println("oh hell");
	    }
	    return nothing;
}
    public void sipstart() throws SocketException, UnknownHostException, MessageAttributeParsingException, MessageHeaderParsingException, UtilityException, IOException, MessageAttributeException {
    	System.out.println("startSIPPPPPPPPPPPPPPPPPPPPP");
    	BindingLifetimeTest stunn=new BindingLifetimeTest("163.17.21.188", 3478);
		stunn.test();
		stun=stunn.ma.getAddress().toString();
		port=stunn.ma.getPort();
		System.out.println("stun:"+stun+":"+port);
		ListeningPoint= InetAddress.getLocalHost().getHostAddress();
		System.out.println("ListeningPoint:"+ListeningPoint);
		new Shootist().init();
	
    }
    
    
    public void SendInvite(){
        try
        {
          String transport = "udp";
          
          ArrayList viaHeaders = new ArrayList();
          
          ViaHeader viaHeader = headerFactory.createViaHeader(stun.toString(), 
           port, 
            transport, null);
          

          viaHeaders.add(viaHeader);
          


          MaxForwardsHeader maxForwardsHeader = headerFactory.createMaxForwardsHeader(70);
          


          CallIdHeader callIdHeader = sipProvider.getNewCallId();
          


          cseq += 1L;
          CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(cseq, Request.INVITE);
          
          javax.sip.address.Address fromAddress = addressFactory.createAddress("sip:" + user + "@open-ims.test");
          
          FromHeader fromHeader = headerFactory.createFromHeader(fromAddress, "12345");
          
          javax.sip.address.Address toAddress = addressFactory.createAddress("sip:" + invite_receive + "@open-ims.test"); 

          ToHeader toHeader = headerFactory.createToHeader(toAddress, null);
     
          MaxForwardsHeader maxForwards = headerFactory
            .createMaxForwardsHeader(70);
          URI requestURI = addressFactory.createURI("sip:" + invite_receive + "@open-ims.test");
          
          Request request = messageFactory.createRequest(requestURI, Request.INVITE, callIdHeader, cSeqHeader, fromHeader, toHeader, viaHeaders, maxForwards);
          
          javax.sip.address.Address routeaddress = addressFactory.createAddress("sip:orig@163.17.21.186:5060;lr");
          RouteHeader routeHeader = headerFactory.createRouteHeader(routeaddress);
          
          ContentTypeHeader ContentTypeHeader = headerFactory.createContentTypeHeader("application", "sdp");


          String sdpData = "v=0\r\n"
                  + "o=4855 13760799956958020 13760799956958021"
                  + " IN IP4  163.17.21.86\r\n" + "s=mysession session\r\n"
                  + "p=+46 8 52018010\r\n" + "c=IN IP4  163.17.21.86\r\n"
                  + "t=0 0\r\n" + "m=audio 6022 RTP/AVP 0 4 18\r\n"

                  // bandwith
                  + "b=AS:25.4\r\n"
                  // precondition mechanism
                  + "a=curr:qos local none\r\n"
                  + "a=curr:qos remote none\r\n"
                  + "a=des:qos mandatory local sendrec\r\n"
                  + "a=des:qos none remote sendrec\r\n"


                  + "a=rtpmap:0 PCMU/8000\r\n" + "a=rtpmap:4 G723/8000\r\n"
                  + "a=rtpmap:18 G729A/8000\r\n" + "a=ptime:20\r\n";
          byte[] contents = sdpData.getBytes();

          request.setContent(contents, ContentTypeHeader);
          
          
          
        
          if (Request.INVITE.equals("INVITE"))
          {
            Header AcceptContactH = headerFactory.createAcceptHeader("Accept-Contact", "*; mobility=\"fixed\"");
            Header RejectContactH = headerFactory.createHeader("Reject-Contact", "*; mobility=\"mobile\"");
            Header RequestDispositionH = headerFactory.createHeader("Request-Disposition", "no-fork");
            request.addHeader(AcceptContactH);
            request.addHeader(RejectContactH);
            request.addHeader(RequestDispositionH);
          }
          request.addHeader(contactH);
          


          request.addHeader(routeHeader);
          
          request.addHeader(callIdHeader);
          
          request.addHeader(cSeqHeader);
          
          request.addHeader(fromHeader);
          
          request.addHeader(toHeader);
          
          request.addHeader(maxForwardsHeader);
          
          request.addHeader(viaHeader);
          



          request.addHeader(ContentTypeHeader);
          






          javax.sip.address.Address fromNameAddress = addressFactory.createAddress(fromAddress.toString());
          

          HeaderFactoryImpl headerFactoryImpl = new HeaderFactoryImpl();
          
          AllowHeader allow1 = headerFactory.createAllowHeader(Request.INVITE);
          request.addHeader(allow1);
          AllowHeader allow2 = 
            headerFactory.createAllowHeader("PRACK");
          request.addHeader(allow2);
          AllowHeader allow3 = 
            headerFactory.createAllowHeader("UPDATE");
          request.addHeader(allow3);
          AllowHeader allow4 = 
            headerFactory.createAllowHeader("ACK");
          request.addHeader(allow4);
          AllowHeader allow5 = 
            headerFactory.createAllowHeader("CANCEL");
          request.addHeader(allow5);
          AllowHeader allow6 = 
            headerFactory.createAllowHeader("BYE");
          request.addHeader(allow6);
          AllowHeader allow7 = 
            headerFactory.createAllowHeader("REFER");
          request.addHeader(allow7);
          AllowHeader allow8 = 
            headerFactory.createAllowHeader("NOTIFY");
          request.addHeader(allow8);
          
          SupportedHeader supported1 = 
            headerFactory.createSupportedHeader("100rel");
          request.addHeader(supported1);
          SupportedHeader supported2 = 
            headerFactory.createSupportedHeader("preconditions");
          request.addHeader(supported2);
          SupportedHeader supported3 = 
            headerFactory.createSupportedHeader("path");
          request.addHeader(supported3);
          
          RequireHeader require1 = 
            headerFactory.createRequireHeader("sec-agree");
          request.addHeader(require1);
          RequireHeader require2 = 
            headerFactory.createRequireHeader("preconditions");
          request.addHeader(require2);
          
          SecurityClientHeader secClient = 
            headerFactoryImpl.createSecurityClientHeader();
          secClient.setSecurityMechanism("ipsec-3gpp");
          secClient.setAlgorithm("hmac-md5-96");
          secClient.setEncryptionAlgorithm("des-cbc");
          secClient.setSPIClient(10000);
          secClient.setSPIServer(10001);
          secClient.setPortClient(5063);
          secClient.setPortServer(4166);
          request.addHeader(secClient);
          
          PAccessNetworkInfoHeader accessInfo = 
            headerFactoryImpl.createPAccessNetworkInfoHeader();
          accessInfo.setAccessType("3GPP-UTRAN-TDD");
          accessInfo.setUtranCellID3GPP("0123456789ABCDEF");
          request.addHeader(accessInfo);
          
          PrivacyHeader privacy = headerFactoryImpl.createPrivacyHeader("header");
          request.addHeader(privacy);
          PrivacyHeader privacy2 = headerFactoryImpl.createPrivacyHeader("user");
          request.addHeader(privacy2);
          

          PPreferredIdentityHeader preferredID = 
            headerFactoryImpl.createPPreferredIdentityHeader(fromNameAddress);
          request.addHeader(preferredID);
          

          PPreferredServiceHeader preferredService = 
            headerFactoryImpl.createPPreferredServiceHeader();
          preferredService.setApplicationIdentifiers("3gpp-service-ims.icis.mmtel");
          request.addHeader(preferredService);
          

          PAssertedServiceHeader assertedService = 
            headerFactoryImpl.createPAssertedServiceHeader();
          assertedService.setApplicationIdentifiers("3gpp-service-ims.icis.mmtel");
          request.addHeader(assertedService);
          










          String fromSipAddress = "open-ims.test";
          String toSipAddress = "open-ims.test";
          


          PCalledPartyIDHeader calledPartyID = 
            headerFactoryImpl.createPCalledPartyIDHeader(toAddress);
          request.addHeader(calledPartyID);
          

          PVisitedNetworkIDHeader visitedNetworkID1 = 
            headerFactoryImpl.createPVisitedNetworkIDHeader();
          visitedNetworkID1.setVisitedNetworkID(fromSipAddress
            .substring(fromSipAddress.indexOf("@") + 1));
          PVisitedNetworkIDHeader visitedNetworkID2 = 
            headerFactoryImpl.createPVisitedNetworkIDHeader();
          visitedNetworkID2.setVisitedNetworkID(toSipAddress
            .substring(toSipAddress.indexOf("@") + 1));
          request.addHeader(visitedNetworkID1);
          request.addHeader(visitedNetworkID2);
          


          PAssociatedURIHeader associatedURI1 = 
            headerFactoryImpl.createPAssociatedURIHeader(toAddress);
          PAssociatedURIHeader associatedURI2 = 
            headerFactoryImpl.createPAssociatedURIHeader(fromNameAddress);
          request.addHeader(associatedURI1);
          request.addHeader(associatedURI2);
          


          PAssertedIdentityHeader assertedID = 
            headerFactoryImpl.createPAssertedIdentityHeader(
            addressFactory.createAddress(requestURI));
          request.addHeader(assertedID);
          
          TelURL tel = addressFactory.createTelURL("+1-201-555-0123");
          javax.sip.address.Address telAddress = addressFactory.createAddress(tel);
          toAddress.setDisplayName(invite_receive);
          PAssertedIdentityHeader assertedID2 = 
            headerFactoryImpl.createPAssertedIdentityHeader(telAddress);
          request.addHeader(assertedID2);
          


          PChargingFunctionAddressesHeader chargAddr = 
            headerFactoryImpl.createPChargingFunctionAddressesHeader();
          chargAddr.addChargingCollectionFunctionAddress("test1.ims.test");
          chargAddr.addEventChargingFunctionAddress("testevent");
          request.addHeader(chargAddr);
          

          PChargingVectorHeader chargVect = 
            headerFactoryImpl.createChargingVectorHeader("icid");
          chargVect.setICIDGeneratedAt("icidhost");
          chargVect.setOriginatingIOI("origIOI");
          chargVect.setTerminatingIOI("termIOI");
          request.addHeader(chargVect);
          

          PMediaAuthorizationHeader mediaAuth1 = 
            headerFactoryImpl.createPMediaAuthorizationHeader("13579bdf");
          PMediaAuthorizationHeader mediaAuth2 = 
            headerFactoryImpl.createPMediaAuthorizationHeader("02468ace");
          request.addHeader(mediaAuth1);
          request.addHeader(mediaAuth2);
          


          PathHeader path1 = 
            headerFactoryImpl.createPathHeader(fromNameAddress);
          PathHeader path2 = 
            headerFactoryImpl.createPathHeader(toAddress);
          request.addHeader(path1);
          request.addHeader(path2);
          







          inviteTidd = sipProvider.getNewClientTransaction(request);
          


          inviteTidd.sendRequest();
          if (Request.REGISTER.equals("REGISTER")) {
            dialog = inviteTidd.getDialog();
          } else if (Request.INVITE.equals("INVITE")) {
            dialogcall = inviteTidd.getDialog();
          }
        }
        catch (Exception e)
        {
          e.printStackTrace();
        }
      }
    

    
    
    
    /**
     * Process the bye request.
     */
    public void processBye(RequestEvent requestEvent,
            ServerTransaction serverTransactionId) {
        SipProvider sipProvider = (SipProvider) requestEvent.getSource();
        Request request = requestEvent.getRequest();
        Dialog dialog = requestEvent.getDialog();
        System.out.println("local party = " + dialog.getLocalParty());
        try {
            System.out.println("Shootist:  got a bye sending OK.");
            Response response = messageFactory.createResponse(200, request);
            serverTransactionId.sendResponse(response);
            System.out.println("Dialog State is "
                    + serverTransactionId.getDialog().getState());

        } catch (Exception ex) {
            ex.printStackTrace();
            junit.framework.TestCase.fail("Exit JVM");

        }
    }

  


    
    public void processIOException(IOExceptionEvent exceptionEvent) {
        System.out.println("IOException");

    }

    public void processTransactionTerminated(
            TransactionTerminatedEvent transactionTerminatedEvent) {
        if (transactionTerminatedEvent.isServerTransaction())
            System.out.println("Transaction terminated event recieved"
                    + transactionTerminatedEvent.getServerTransaction());
        else
            System.out.println("Transaction terminated "
                    + transactionTerminatedEvent.getClientTransaction());

    }

    public void processDialogTerminated(
            DialogTerminatedEvent dialogTerminatedEvent) {
        System.out.println("Dialog terminated event recieved");
        Dialog d = dialogTerminatedEvent.getDialog();
        System.out.println("Local Party = " + d.getLocalParty());

    }

}