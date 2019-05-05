package auth;
import javax.sdp.*;

import gov.nist.javax.sdp.SessionDescriptionImpl;
import gov.nist.javax.sdp.parser.SDPAnnounceParser;

import gov.nist.javax.sip.clientauthutils.DigestServerAuthenticationHelper;

import gov.nist.javax.sip.header.HeaderFactoryImpl;

import gov.nist.javax.sip.header.ims.*;

import javax.sip.*;
import javax.sip.address.*;
import javax.sip.address.URI;
import javax.sip.header.*;
import javax.sip.message.*;

import Callee.PCS_RTP_Callee;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.*;
import Caller.PCS_RTP_Caller;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.test.BindingLifetimeTest;
import de.javawi.jstun.util.UtilityException;

import javax.sip.ServerTransaction;




/**
 * <p>This class is a UAC template.</p>
 * <p>Exemplifies the creation and parsing of the SIP P-Headers for IMS</p>
 *
 * <p>based on examples.simplecallsetup, by M. Ranganathan</p>
 * <p>issued by Miguel Freitas (IT) PT-Inovacao</p>
 */


public class Shootisttest implements SipListener {
	
	 private static ClientTransaction inviteTidClientCall;

    private static SipProvider sipProvider;

    private static AddressFactory addressFactory;

    private static MessageFactory messageFactory;

    private static HeaderFactory headerFactory;

    private static SipStack sipStack;

    private ContactHeader contactHeader;

    private ListeningPoint udpListeningPoint;

    private ClientTransaction inviteTidClient;
    
    public Request request;

    private Dialog dialog;


    
    String transport = "udp";
    
    String peerHostPort = "163.17.21.221:5060";
    

    
	long invco = 1;
	
	String sdpData;
    
	private static long cseq = 0L;
    
    private static Header contactH;
    
    private static Dialog dialogCall;
    
    private static Dialog dialogCall2;
    
    protected static ServerTransaction inviteTidserver;
    
    public static String localIP;
    private static String IPcallee;
    public static String RTPportcallee;
    public static String RTCPportcallee;
    public static int localRtpPort;
    public static int localRtcpPort;
    public static boolean inPhoneCallProcess = false;
    public static boolean inReferProcess = false;
    
  //  protected static ServerTransaction inviteTid;	 
    
    private static Response okResponse;
    
    public Request inviteRequest;
    
    public int answer=0;
    
    private static String IPcaller;
	  
	  private static String RTPportcaller;
	  
	  private static String RTCPportcaller;

	  private static BindingLifetimeTest getstun = new BindingLifetimeTest("163.17.21.221", 3478);
    
	  public static  String MyAddress;
	    
	  public static  int MyPort;
	    
    public class MyTimerTask extends TimerTask {
        Shootisttest shootisttest;
        public MyTimerTask(Shootisttest shootisttest) {
            this.shootisttest = shootisttest;

        }

		public void run() {
			System.out.println("send200 OK!!GOOD");
			shootisttest.sendInviteOK();
        }

    }
    
    private void STUNPut()
		    throws SocketException, UnknownHostException, MessageAttributeParsingException, MessageHeaderParsingException, UtilityException, IOException, MessageAttributeException
		  {
		    getstun.test();
		    MyPort = getstun.ma.getPort();
		    MyAddress = getstun.ma.getAddress().toString();
		    
		    System.out.println("MyPort"+MyPort);
		    System.out.println("MyAddress"+MyAddress);
		  }

public void getlocalIP()
	    throws UnknownHostException
	  {
	    localIP = InetAddress.getLocalHost().getHostAddress();
	    System.out.println("localIP"+localIP);
	  }
    
    
    private  void recordingSocket(String IPcallee, String RTPportcallee, String RTCPportcallee)
    {
      Shootisttest.IPcallee = IPcallee;    
      
      Shootisttest.RTPportcallee = RTPportcallee;
      Shootisttest.RTCPportcallee = RTCPportcallee;
      
    }
    
    public String getCalleeIP()
    {
    	
      return IPcallee.replaceAll("\\s+", "");
    }
    
    public String getCalleeRTPport()
    {
      return RTPportcallee.replaceAll(" ", "");
    }
    
    public String getCalleeRTCPport()
    {
      return RTCPportcallee.replaceAll(" ", "");
    }
    
  
    private void recordingSocket2(String IPcaller, String RTPportcaller, String RTCPportcaller)
	  {
	    Shootisttest.IPcaller = IPcaller;
	    Shootisttest.RTPportcaller = RTPportcaller;
	    Shootisttest.RTCPportcaller = RTCPportcaller;
	    
	  }
	 
	 public String getCallerIP()
	  {
	    return IPcaller.replaceAll("\\s+", "");
	  }
	  
	  public String getCallerRTPport()
	  {
	    return RTPportcaller.replaceAll(" ", "");
	  }
	  
	  public String getCallerRTCPport()
	  {
	    return RTCPportcaller.replaceAll(" ", "");
	  }
	  

    
    
    
    class ByeTask  extends TimerTask {
        Dialog dialog;
        public ByeTask(Dialog dialog)  {
            this.dialog = dialog;
        }
        public void run () {
            try {
               Request byeRequest = this.dialog.createRequest(Request.BYE);
               ClientTransaction ct = sipProvider.getNewClientTransaction(byeRequest);
               dialog.sendRequest(ct);
            } catch (Exception ex) {
                ex.printStackTrace();
                junit.framework.TestCase.fail("Exit JVM");
            }

        }

    }

    private static final String usageString = "java "
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
        if (request.getMethod().equals(Request.INVITE)) {
        	
        	System.out.println("processInvite_processInvite_processInvite");
            processInvite(requestReceivedEvent, serverTransactionId);
            System.out.println("processInvite_processInvite_processInvite_END");
        } else if (request.getMethod().equals(Request.ACK)) {
        	System.out.println("processAck_processAck_processAck");
            processAck(requestReceivedEvent, serverTransactionId);
            System.out.println("processAck_processAck_processAck_END");
            System.out.println("processBye");
            SendBye();
            
            
        } else if (request.getMethod().equals(Request.BYE)) {
            processBye2(requestReceivedEvent, serverTransactionId);
        } else if (request.getMethod().equals(Request.CANCEL)) {
            processCancel(requestReceivedEvent, serverTransactionId);
        }
        if (request.getMethod().equals(Request.BYE)){
            processBye(request, serverTransactionId);
    	}

    }
    
    public void processInvite(RequestEvent requestEvent, ServerTransaction serverTransaction)
    {
      SipProvider sipProvider = (SipProvider)requestEvent.getSource();
      Request request = requestEvent.getRequest();
      


      HeaderFactoryImpl headerFactoryImpl = (HeaderFactoryImpl)headerFactory;
      



      ListIterator li = null;
      AllowHeader allow = null;
      String allowMethods = new String();
      li = request.getHeaders("Allow");
      try
      {
        while (li.hasNext())
        {
          allow = (AllowHeader)li.next();
          allowMethods = allowMethods.concat(allow.getMethod()).concat(" ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("\n(!) Exception getting Allow header! - " + ex);
      }
      RequireHeader require = null;
      String requireOptionTags = new String();
      li = null;
      li = request.getHeaders("Require");
      try
      {
        while (li.hasNext())
        {
          require = (RequireHeader)li.next();
          requireOptionTags = requireOptionTags
            .concat(require.getOptionTag())
            .concat(" ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("\n(!) Exception getting Require header! - " + ex);
      }
      SupportedHeader supported = null;
      String supportedOptionTags = new String();
      li = request.getHeaders("Supported");
      try
      {
        while (li.hasNext())
        {
          supported = (SupportedHeader)li.next();
          supportedOptionTags = supportedOptionTags
            .concat(supported.getOptionTag())
            .concat(" ");
        }
      }
      catch (NullPointerException ex)
      {
        System.out.println("\n(!) Exception getting Supported header! - " + ex);
      }
      try
      {
        PCalledPartyIDHeader calledParty = (PCalledPartyIDHeader)
          request.getHeader("P-Called-Party-ID");
        if (calledParty != null) {
          System.out.println(".: P-Called-Party-ID = " + 
            calledParty.getAddress().toString());
        } else {
          System.out.println(".: NOT received P-Called-Party-ID ! ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Called-Party-ID header! - " + ex);
      }
      try
      {
        ListIterator associatedURIList = request.getHeaders("P-Associated-URI");
        if (associatedURIList != null)
        {
          System.out.print(".: P-Associated-URI = ");
          while (associatedURIList.hasNext())
          {
            PAssociatedURIHeader associatedURI = (PAssociatedURIHeader)associatedURIList.next();
            
            System.out.print(associatedURI.getAssociatedURI().toString());
            if (associatedURIList.hasNext()) {
              System.out.print(", ");
            }
          }
        }
        else
        {
          System.out.println(".: NOT received P-Associated-URI ! ");
        }
        System.out.print("\n");
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Associated-URI header! - " + ex);
      }
      PAccessNetworkInfoHeader accessInfo = null;
      try
      {
        accessInfo = (PAccessNetworkInfoHeader)
          request.getHeader("P-Access-Network-Info");
        if (accessInfo != null)
        {
          System.out.print(".: P-Access-Network-Info: Access Type = " + 
            accessInfo.getAccessType());
          if (accessInfo.getAccessType().equalsIgnoreCase("3GPP-UTRAN-TDD")) {
            System.out.print(" - Cell ID = " + 
              accessInfo.getUtranCellID3GPP());
          }
        }
        else
        {
          System.out.println(".: NOT received P-Access-Network-Info ! ");
        }
        System.out.println("");
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Access-Network-Info header! - " + ex);
      }
      if (accessInfo != null)
      {
        PAccessNetworkInfo accessInfoClone = 
          (PAccessNetworkInfo)accessInfo.clone();
        
        System.out.println("--> clone = " + accessInfoClone.toString());
        System.out.println("--> equals? " + accessInfoClone.equals(accessInfo));
      }
      try
      {
        ListIterator visitedNetList = request.getHeaders("P-Visited-Network-ID");
        if (visitedNetList != null)
        {
          System.out.print(".: P-Visited-Network-ID = ");
          while (visitedNetList.hasNext())
          {
            PVisitedNetworkIDHeader visitedID = 
              (PVisitedNetworkIDHeader)visitedNetList.next();
            System.out.print(visitedID.getVisitedNetworkID());
            if (visitedNetList.hasNext()) {
              System.out.print(", ");
            }
          }
          System.out.print("\n");
        }
        else
        {
          System.out.print(".: NOT received P-Visited-Network-ID ! ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Visited-Network-ID header! - " + ex);
      }
      try
      {
        ListIterator privacyList = request.getHeaders("Privacy");
        if ((privacyList != null) && (privacyList.hasNext()))
        {
          System.out.print(".: Privacy = ");
          while (privacyList.hasNext())
          {
            PrivacyHeader privacy = 
              (PrivacyHeader)privacyList.next();
            System.out.print(privacy.getPrivacy());
            if (privacyList.hasNext()) {
              System.out.print("; ");
            }
          }
          System.out.println("");
        }
        else
        {
          System.out.println(".: NOT received Privacy ! ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting Privacy header! - " + ex);
      }
      try
      {
        PPreferredIdentityHeader preferredID = (PPreferredIdentityHeader)
          request.getHeader("P-Preferred-Identity");
        if (preferredID != null) {
          System.out.println(".: P-Preferred-Identity = " + preferredID.getAddress().toString());
        } else {
          System.out.println(".: NOT received P-Preferred-Identity ! ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Preferred-Identity header! - " + ex);
      }
      try
      {
        ListIterator assertedIDList = 
          request.getHeaders("P-Asserted-Identity");
        if ((assertedIDList != null) && (assertedIDList.hasNext()))
        {
          System.out.print(".: P-Asserted-Identity = ");
          while (assertedIDList.hasNext())
          {
            PAssertedIdentityHeader assertedID = 
              (PAssertedIdentityHeader)assertedIDList.next();
            System.out.print(assertedID.getAddress().toString());
            if (assertedIDList.hasNext()) {
              System.out.print(", ");
            }
          }
          System.out.println("");
        }
        else
        {
          System.out.println(".: NOT received P-Asserted-Identity... ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Asserted-Identity header! - " + ex);
      }
      try
      {
        PChargingFunctionAddressesHeader chargAddr = (PChargingFunctionAddressesHeader)
          request.getHeader("P-Charging-Function-Addresses");
        if (chargAddr != null)
        {
          Iterator param = chargAddr.getParameterNames();
          
          System.out.print(".: P-Charging-Function-Addresses = ");
          if (param != null) {
            while (param.hasNext())
            {
              String paramName = (String)param.next();
              System.out.print(paramName + "=" + chargAddr.getParameter(paramName));
              if (param.hasNext()) {
                System.out.print(", ");
              }
            }
          }
          System.out.println("");
        }
        else
        {
          System.out.println(".: NOT containing P-Charging-Function-Addresses... ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Charging-Function-Addresses header! - " + ex);
      }
      try
      {
        PChargingVectorHeader chargVect = (PChargingVectorHeader)
          request.getHeader("P-Charging-Vector");
        if (chargVect != null)
        {
          Iterator param = chargVect.getParameterNames();
          
          System.out.print(".: P-Charging-Vector = ");
          if ((param != null) && (param.hasNext())) {
            while (param.hasNext())
            {
              String paramName = (String)param.next();
              System.out.print(paramName + "=" + 
                chargVect.getParameter(paramName));
              if (param.hasNext()) {
                System.out.print(", ");
              }
            }
          }
          System.out.println("");
        }
        else
        {
          System.out.println(".: NOT containing P-Charging-Vector... ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Charging-Vector header! - " + ex);
      }
      try
      {
        ListIterator mediaAuthList = request.getHeaders("P-Media-Authorization");
        if (mediaAuthList != null)
        {
          System.out.print(".: P-Media-Authorization = ");
          while (mediaAuthList.hasNext())
          {
            PMediaAuthorizationHeader mediaAuth = 
              (PMediaAuthorizationHeader)mediaAuthList.next();
            System.out.print(mediaAuth.getToken());
            if (mediaAuthList.hasNext()) {
              System.out.print(", ");
            }
          }
          System.out.println("");
        }
        else
        {
          System.out.println(".: NOT containing P-Media-Authorization... ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting P-Media-Authorization header! - " + ex);
      }
      try
      {
        ListIterator secClientList = request.getHeaders("Security-Client");
        if (secClientList != null) {
          while (secClientList.hasNext()) {
            System.out.println(".: " + 
              ((SecurityClientHeader)secClientList.next()).toString());
          }
        } else {
          System.out.println(".: NOT containing Security-Client header... ");
        }
      }
      catch (Exception ex)
      {
        System.out.println("(!) Exception getting Security-Client header! - " + ex);
      }
      SecurityServerList secServerList = null;
      if (requireOptionTags.indexOf("sec-agree") != -1)
      {
        secServerList = new SecurityServerList();
        try
        {
          SecurityServerHeader secServer1 = 
            headerFactoryImpl.createSecurityClientHeader();
          secServer1.setSecurityMechanism("ipsec-3gpp");
          secServer1.setAlgorithm("hmac-md5-96");
          secServer1.setEncryptionAlgorithm("des-cbc");
          secServer1.setSPIClient(10000);
          secServer1.setSPIServer(10001);
          secServer1.setPortClient(5063);
          secServer1.setPortServer(4166);
          secServer1.setPreference(0.1F);
          
          SecurityServerHeader secServer2 = 
            headerFactoryImpl.createSecurityClientHeader();
          secServer2.setSecurityMechanism("ipsec-3gpp");
          secServer2.setAlgorithm("hmac-md5-96");
          secServer2.setEncryptionAlgorithm("des-cbc");
          secServer2.setSPIClient(20000);
          secServer2.setSPIServer(20001);
          secServer2.setPortClient(5073);
          secServer2.setPortServer(4286);
          secServer2.setPreference(0.5F);
          
          request.addHeader(secServer1);
          request.addHeader(secServer2);
        }
        catch (Exception ex)
        {
          System.out.println("(!) Exception adding Security-Server header : " + ex);
        }
      }
      ListIterator<Header> pathList = request.getHeaders("Path");
      if ((pathList != null) && (pathList.hasNext()))
      {
        System.out.print(".: Path received : ");
        while (pathList.hasNext())
        {
          PathHeader path = (PathHeader)pathList.next();
          if (path != null) {
            System.out.print(path.getAddress().toString());
          }
          if (pathList.hasNext()) {
            System.out.print(", ");
          }
        }
        System.out.println("");
      }
      
      String str = new String(request.getRawContent(), StandardCharsets.UTF_8);
      try
      {
        new Shootisttest();SDPParser2(str);
      }
      catch (ParseException|SdpException e)
      {
        e.printStackTrace();
      }
      
      try
      {
        System.out.println("shootme: got an Invite sending Ringing");
        
        Response response = messageFactory.createResponse(180, 
          request);
        
        AllowHeader allow1 = 
          headerFactory.createAllowHeader("ACK");
        response.addHeader(allow1);
        AllowHeader allow2 = 
          headerFactory.createAllowHeader("CANCEL");
        response.addHeader(allow2);
        AllowHeader allow3 = 
          headerFactory.createAllowHeader("BYE");
        response.addHeader(allow3);
        
        ServerTransaction st = requestEvent.getServerTransaction();
        if (st == null) {
          st = sipProvider.getNewServerTransaction(request);
        }
        dialogCall2 = st.getDialog();
        
        st.sendResponse(response);
        
      //  PCS_RTP_Callee.ui.setStateText("Running");
        

        okResponse = messageFactory.createResponse(200, 
          request);
        javax.sip.address.Address address = addressFactory.createAddress("Shootme <sip:"+MyAddress+":"+MyPort+">");
        ContactHeader contactHeader = headerFactory
          .createContactHeader(address);
        response.addHeader(contactHeader);
        

        ContentTypeHeader contentTypeHeader = headerFactory.createContentTypeHeader("application", "sdp");
        okResponse.setContent(SDPsetting(), contentTypeHeader);
        

        ToHeader toHeader = (ToHeader)okResponse.getHeader("To");
        toHeader.setTag("4321");
        okResponse.addHeader(contactHeader);
        inviteTidserver = st;
        

        this.inviteRequest = request;
        if ((secServerList != null) && (!secServerList.isEmpty()))
        {
          RequireHeader requireHeader = headerFactory.createRequireHeader("sec-agree");
          okResponse.setHeader(requireHeader);
          
          okResponse.setHeader(secServerList);
        }
        System.out.print("send200 OK!!");
        new Timer().schedule(new MyTimerTask(this), 100);	
        
      }
      catch (Exception ex)
      {
        ex.printStackTrace();
        System.exit(0);
      }
    }
    
    public void processAck(RequestEvent requestEvent, ServerTransaction serverTransaction)
    {
    	System.out.println("shootme: got an ACK!xxxxxxxxxxxx ");
    
    	new PCS_RTP_Caller().Port2();
     	new PCS_RTP_Caller().Media2();
    	
     
      try
      {
        System.out.println("shootme: got an ACK! ");
        System.out.println("Dialog State = " + dialogCall.getState());
        SipProvider provider = (SipProvider)requestEvent.getSource();

        Request byeRequest = dialogCall.createRequest("BYE");
        inviteTidClientCall = provider.getNewClientTransaction(byeRequest);
        
       
      }
      catch (Exception ex)
      {
        ex.printStackTrace();
      }
    }
    
    public void processBye2(RequestEvent requestEvent, ServerTransaction serverTransactionId)
    {
      SipProvider sipProvider = (SipProvider)requestEvent.getSource();
      Request request = requestEvent.getRequest();
      Dialog dialogcall = requestEvent.getDialog();
      System.out.println("local party = " + dialogcall.getLocalParty());
      try
      {
        System.out.println("shootme:  got a bye sending OK.");
        Response response = messageFactory.createResponse(200, request);
        serverTransactionId.sendResponse(response);
        System.out.println("Dialog State is " + 
          serverTransactionId.getDialog().getState());
      }
      catch (Exception ex)
      {
        ex.printStackTrace();
        System.exit(0);
      }
      new PCS_RTP_Callee().EndSession();
    }

    public void processCancel(RequestEvent requestEvent, ServerTransaction serverTransactionId)
    {
      SipProvider sipProvider = (SipProvider)requestEvent.getSource();
      Request request = requestEvent.getRequest();
      try
      {
        System.out.println("shootme:  got a cancel.");
        if (serverTransactionId == null)
        {
          System.out.println("shootme:  null tid.");
          return;
        }
        Response response = messageFactory.createResponse(200, request);
        serverTransactionId.sendResponse(response);
        if (dialogCall.getState() != DialogState.CONFIRMED)
        {
          response = messageFactory.createResponse(
            487, this.inviteRequest);
          inviteTidserver.sendResponse(response);
        }
       // PCS_RTP_Calle.ui.setStateText("Cancel!");
      }
      catch (Exception ex)
      {
        ex.printStackTrace();
        System.exit(0);
      }
    }
    
    
    public void processBye(Request request, ServerTransaction serverTransactionId)
    {
      System.out.println("shootist:  got a bye .");
      new PCS_RTP_Caller().EndSession2();
      try
      {
        if (serverTransactionId == null)
        {
          System.out.println("shootist:  null TID.");
          return;
        }
        Dialog dialog = serverTransactionId.getDialog();
        System.out.println("Dialog State = " + dialog.getState());
        Response response = messageFactory.createResponse(200, request);
        serverTransactionId.sendResponse(response);
        System.out.println("shootist:  Sending OK.");
        System.out.println("Dialog State = " + dialog.getState());
      }
      catch (Exception ex)
      {
        ex.printStackTrace();
        System.exit(0);
      }
    }


    public void processInviteOK(Response ok, ClientTransaction ct)
    {

        HeaderFactoryImpl headerFactoryImpl =
            (HeaderFactoryImpl) headerFactory;

        try
        {

            RequireHeader require = null;
            String requireOptionTags = new String();
            ListIterator li = ok.getHeaders(RequireHeader.NAME);
            if (li != null) {
                try {
                    while(li.hasNext())
                    {
                        require = (RequireHeader) li.next();
                        requireOptionTags = requireOptionTags
                            .concat( require.getOptionTag())
                            .concat(" ");
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
            if (requireOptionTags.indexOf("sec-agree") != -1)
            {
                ListIterator secServerReceived =
                    ok.getHeaders(SecurityServerHeader.NAME);
                if (secServerReceived != null && secServerReceived.hasNext())
                {
                    System.out.println(".: Security-Server received: ");

                     while (secServerReceived.hasNext())
                    {
                        SecurityServerHeader security = null;
                        try {
                            security = (SecurityServerHeader) secServerReceived.next();
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
            ackRequest = dialogCall.createAck( cseq.getSeqNumber() );

            if (secVerifyList != null && !secVerifyList.isEmpty())
            {
                RequireHeader requireSecAgree = headerFactory.createRequireHeader("sec-agree");
                ackRequest.setHeader(requireSecAgree);

                ackRequest.setHeader(secVerifyList);
            }

            System.out.println("Sending ACK");
            dialogCall.sendAck(ackRequest);
            
            
            new PCS_RTP_Caller().Port();
            new PCS_RTP_Caller().Media();
       //     new PCS_RTP_Caller().addNewParticipant(remoteIP, remoteRtpPort, remoteRtcpPort, localRtpPort, localRtcpPort);
       //     new PCS_RTP_Caller().startTalking();
            
        }
        catch (Exception ex)
        {
            System.out.println("(!) Exception sending ACK to 200 OK " +
                    "response to INVITE : " + ex);
        }
    }



       // Save the created ACK request, to respond to retransmitted 2xx
       private Request ackRequest;

       public void processResponse(ResponseEvent responseReceivedEvent) {
       	System.out.println("Got a response");
           Response response = (Response) responseReceivedEvent.getResponse();
           ClientTransaction tid = responseReceivedEvent.getClientTransaction();
           CSeqHeader cseq = (CSeqHeader) response.getHeader(CSeqHeader.NAME);

           System.out.println("Response received : Status Code = "
                   + response.getStatusCode() + " " + cseq);


           if (tid == null) {

               // RFC3261: MUST respond to every 2xx
               if (ackRequest!=null && dialogCall2!=null) {
                  System.out.println("re-sending ACK");
                  try {
                     dialogCall.sendAck(ackRequest);
                  } catch (SipException se) {
                     se.printStackTrace();
                  }
               }
               return;
           }
           /*
           // If the caller is supposed to send the bye
           if ( Shootme.callerSendsBye && !byeTaskRunning) {
               byeTaskRunning = true;
               new Timer().schedule(new ByeTask(dialog), 2000) ;
           }
           
           System.out.println("transaction state is " + tid.getState());
           System.out.println("Dialog = " + tid.getDialog());
           System.out.println("Dialog State is " + tid.getDialog().getState());
   */
           try {

               if (response.getStatusCode() == Response.OK && 
               	cseq.getMethod().equals(Request.REGISTER)) {
               	System.out.println("Sending ACK CN!!!!!! REGISTER OK");
               	
               } else if (response.getStatusCode() == Response.UNAUTHORIZED) {  
            /*	   
           		AuthenticationHelper authenticationHelper = 
                           ((SipStackExt) sipStack).getAuthenticationHelper(new AccountManagerImpl(), headerFactory);
                       
                      inviteTid = authenticationHelper.handleChallenge(response, tid, sipProvider, 5);
                     
                      inviteTid.sendRequest();
                    
                      invco++;  
             */
            	   register(response);         
             
                        
               }else if (response.getStatusCode() == Response.OK &&
               		cseq.getMethod().equals(Request.INVITE)) {
            	 //  cseq = 0L;
            	//   System.out.println("XXX1");
            	   String str = new String(response.getRawContent(), StandardCharsets.UTF_8);
            	//   System.out.println("XXX2");
            //	   System.out.println(str+"XXX2222222222222222222");
            	   new Shootisttest();SDPParser(str);
            //	   System.out.println("XXX3");
                   processInviteOK(response, tid);
                   
                   
                   
                 } else if (cseq.getMethod().equals(Request.CANCEL) &&
                   		dialog.getState() == DialogState.CONFIRMED) {
                      
                           // oops cancel went in too late. Need to hang up the
                           // dialog.
                           System.out
                                   .println("Sending BYE -- cancel went in too late !!");
                           Request byeRequest = dialog.createRequest(Request.BYE);
                           ClientTransaction ct = sipProvider
                                   .getNewClientTransaction(byeRequest);
                           dialog.sendRequest(ct);
                       }

           } catch (Exception ex) {
               ex.printStackTrace();
               junit.framework.TestCase.fail("Exit JVM");
           }
       }
       
      
       
       public void register(Response response)
       {
         try
         {
           String transport = "udp";
           
           ArrayList viaHeaders = new ArrayList();
           
           ViaHeader viaHeader = headerFactory.createViaHeader(MyAddress, 
             MyPort, 
             transport, null);

           viaHeaders.add(viaHeader);
           


           MaxForwardsHeader maxForwardsHeader = headerFactory.createMaxForwardsHeader(70);
           


           CallIdHeader callIdHeader = (CallIdHeader)response.getHeader("call-id");
           


           cseq += 1L;
           CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(cseq, "REGISTER");
           
           javax.sip.address.Address fromAddress = addressFactory.createAddress("sip:CN@open-ims.test");
           
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
           





           inviteTidClient = sipProvider.getNewClientTransaction(request);
           


           inviteTidClient.sendRequest();
           
           dialog = inviteTidClient.getDialog();
         }
         catch (Exception e)
         {
           e.printStackTrace();
         }
       }  
       
   


    public void processTimeout(javax.sip.TimeoutEvent timeoutEvent) {

        System.out.println("Transaction Time out");
    }

    public void sendCancel() {
        try {
            System.out.println("Sending cancel");
            Request cancelRequest = inviteTidClient.createCancel();
            ClientTransaction cancelTid = sipProvider
                    .getNewClientTransaction(cancelRequest);
            cancelTid.sendRequest();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    

    public void SendInvite() {
        try
        {
          String transport = "udp";
          
          ArrayList viaHeaders = new ArrayList();
          
          ViaHeader viaHeader = headerFactory.createViaHeader(MyAddress, 
           MyPort, 
            transport, null);
          

          viaHeaders.add(viaHeader);        

          MaxForwardsHeader maxForwardsHeader = headerFactory.createMaxForwardsHeader(70);

          CallIdHeader callIdHeader = sipProvider.getNewCallId();

          cseq += 1L;
          CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(cseq, Request.INVITE);
          
          javax.sip.address.Address fromAddress = addressFactory.createAddress("sip:CN@open-ims.test");
          
          FromHeader fromHeader = headerFactory.createFromHeader(fromAddress, "12345");
          
          javax.sip.address.Address toAddress = addressFactory.createAddress("sip:MN@open-ims.test");

          ToHeader toHeader = headerFactory.createToHeader(toAddress, null);
          
          MaxForwardsHeader maxForwards = headerFactory
            .createMaxForwardsHeader(70);
          URI requestURI = addressFactory.createURI("sip:MN@open-ims.test");
          
          Request request = messageFactory.createRequest(requestURI, Request.INVITE, callIdHeader, cSeqHeader, fromHeader, toHeader, viaHeaders, maxForwards);
          
          javax.sip.address.Address routeaddress = addressFactory.createAddress("sip:orig@163.17.21.223:5060;lr");
          RouteHeader routeHeader = headerFactory.createRouteHeader(routeaddress);
          
          ContentTypeHeader ContentTypeHeader = headerFactory.createContentTypeHeader("application", "sdp");
      /*   
          sdpData = "v=0\r\n"
                  + "o=4855 13760799956958020 13760799956958020"
                  + " IN IP4  163.17.21.71\r\n" + "s=mysession session\r\n"
                  + "p=+46 8 52018010\r\n" + "c=IN IP4  163.17.21.71\r\n"
                  + "t=0 0\r\n" + "m=audio 6022 RTP/AVP 0 4 18\r\n"

                  // bandwith
                //  + "b=AS:25.4\r\n"
                  // precondition mechanism
                  + "a=curr:qos local none\r\n"
                  + "a=curr:qos remote none\r\n"
                  + "a=des:qos mandatory local sendrec\r\n"
                  + "a=des:qos none remote sendrec\r\n"


                  + "a=rtpmap:0 PCMU/8000\r\n" + "a=rtpmap:4 G723/8000\r\n"
                  + "a=rtpmap:18 G729A/8000\r\n" + "a=ptime:20\r\n";
          byte[] contents = sdpData.getBytes();*/
          byte[] contents = SDPsetting().getBytes();

          request.setContent(contents, ContentTypeHeader);
      /*    
          if (Request.INVITE.equals("INVITE"))
          {
            Header AcceptContactH = headerFactory.createAcceptHeader("Accept-Contact", "*; mobility=\"fixed\"");
            Header RejectContactH = headerFactory.createHeader("Reject-Contact", "*; mobility=\"mobile\"");
            Header RequestDispositionH = headerFactory.createHeader("Request-Disposition", "no-fork");
            request.addHeader(AcceptContactH);
            request.addHeader(RejectContactH);
            request.addHeader(RequestDispositionH);
          }
     */     
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
          toAddress.setDisplayName("MN");
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
          







          inviteTidClient = sipProvider.getNewClientTransaction(request);
          


          inviteTidClient.sendRequest();
          if (Request.INVITE.equals("REGISTER")) {
            dialog = inviteTidClient.getDialog();
          } else if (Request.INVITE.equals("INVITE")) {
            dialogCall = inviteTidClient.getDialog();
          }
        }
        catch (Exception e)
        {
          e.printStackTrace();
        }
      }
    
    public void sendInviteOK() {
    	//new Timer().schedule(new MyTimerTask(this), 100);	
    	//�]�w�ǥX200OK
    //	answer=1;
        try {
        	/*
        	System.out.println(inviteTid.getState()+"11111111111111111");
        	System.out.println(TransactionState.COMPLETED+"222222222222222222");
        	System.out.println(inviteTid.getDialog().getState()+"333333333333333333333");
        	*/
        	System.out.print(okResponse+"++++++++");
            if (inviteTidserver.getState() != TransactionState.COMPLETED) {
            	
            	 System.out.println("inviteTid.getDialog().getState()=="
                         + inviteTidserver.getDialog().getState());
            	 
            	 
            //	 System.out.println("okResponse=="+okResponse);
                System.out.println("shootme: Dialog state before 200: "
                        + inviteTidserver.getDialog().getState());
    
                inviteTidserver.sendResponse(okResponse);
               // System.out.print(okResponse+"++++++++");
                System.out.println("shootme: Dialog state after 200: "
                        + inviteTidserver.getDialog().getState());
            }
        } catch (SipException ex) {
            ex.printStackTrace();
        } catch (InvalidArgumentException ex) {
            ex.printStackTrace();
        }
    }
    
    
    
    private static String SDPsetting()
    {
      SdpFactory sdpFactory = SdpFactory.getInstance();
      String sdpData = null;
      try
      {
        SessionDescription sd = sdpFactory.createSessionDescription();
        

        Version version = sdpFactory.createVersion(0);
        



        Origin origin = sdpFactory.createOrigin("UA", 123456L, 1234567L, "IN", "IP4", MyAddress);
        




        Connection connection = sdpFactory.createConnection("IN", "IP4", MyAddress);
        



        SessionName sessionname = sdpFactory.createSessionName("Session from UA to Rsc");
        
        sd.setVersion(version);
        sd.setOrigin(origin);
        sd.setConnection(connection);
        sd.setSessionName(sessionname);
        


        String[] format = new String[1];
        format[0] = Integer.toString(0);
        
        Vector mds = new Vector();
        localRtpPort = (int)(Math.random() * 32767.0D + 24576.0D);
        MediaDescription md1 = sdpFactory.createMediaDescription("audio", localRtpPort, 1, "RTP/AVP", format);
        
        Vector attrs1 = new Vector();
        localRtcpPort = (int)(Math.random() * 32767.0D + 24576.0D);
        Attribute attr1 = sdpFactory.createAttribute("rtcp", Integer.toString(localRtcpPort));
        
        Attribute attr2 = sdpFactory.createAttribute("rtpmap", "0 pcmu/8000");
        Attribute attr3 = sdpFactory.createAttribute("recvonly", null);
        attrs1.addElement(attr1);
        attrs1.addElement(attr2);
        attrs1.addElement(attr3);
        
        md1.setAttributes(attrs1);
        mds.addElement(md1);
        sd.setMediaDescriptions(mds);
        
        sdpData = sd.toString();
      }
      catch (SdpException ex)
      {
        System.err.print(ex.toString());
      }
      return sdpData;
    }
    

    private static void SDPParser(String sdpData)
    	    throws ParseException, SdpException
    	  {
    	    SDPAnnounceParser parser = new SDPAnnounceParser(sdpData);
    	    SessionDescriptionImpl sessiondescription = parser.parse();
    	    
    	    Vector attrs = sessiondescription.getAttributes(false);
    	    if (attrs != null)
    	    {
    	      Attribute attrib = (Attribute)attrs.get(0);
    	      System.out.println("attrs = " + attrib.getName());
    	    }
    	    MediaDescription md = 
    	      (MediaDescription)sessiondescription.getMediaDescriptions(false).get(0);
    	    
    	    System.out.println("md attributes " + md.getAttributes(false));
    	    
    	    SessionDescriptionImpl sessiondescription1 = new SDPAnnounceParser(sessiondescription
    	      .toString()).parse();
    	    

    	    new Shootisttest().recordingSocket(sessiondescription1.getConnection().toString().split("IN IP4 ")[1], md.getMedia().toString().split("m=audio | RTP")[1], md.getAttribute("rtcp"));
    	    System.out.println("Callee IP: " + IPcallee/*sessiondescription1.getConnection().toString().split("IN IP4 ")[1]*/);
    	    System.out.println("Callee RTP port: " + RTPportcallee/*md.getMedia().toString().split("m=audio | RTP")[1]*/);
    	    System.out.println("Callee RTCP port: " + RTCPportcallee/*md.getAttribute("rtcp")*/);
    	  }
    
    private static String SDPsetting2()
    {
      SdpFactory sdpFactory = SdpFactory.getInstance();
      String sdpData = null;
      try
      {
        SessionDescription sd = sdpFactory.createSessionDescription();
        

        Version version = sdpFactory.createVersion(0);
        



        Origin origin = sdpFactory.createOrigin("UA", 123456L, 1234567L, "IN", "IP4", MyAddress);
        




        Connection connection = sdpFactory.createConnection("IN", "IP4", MyAddress);
        



        SessionName sessionname = sdpFactory.createSessionName("Session from UA to Rsc");
        
        sd.setVersion(version);
        sd.setOrigin(origin);
        sd.setConnection(connection);
        sd.setSessionName(sessionname);
        


        String[] format = new String[1];
        format[0] = Integer.toString(0);
        
        Vector mds = new Vector();
        localRtpPort = (int)(Math.random() * 32767.0D + 24576.0D);
        MediaDescription md1 = sdpFactory.createMediaDescription("audio", localRtpPort, 1, "RTP/AVP", format);
        
        Vector attrs1 = new Vector();
        localRtcpPort = (int)(Math.random() * 32767.0D + 24576.0D);
        Attribute attr1 = sdpFactory.createAttribute("rtcp", Integer.toString(localRtcpPort));
        
        Attribute attr2 = sdpFactory.createAttribute("rtpmap", "0 pcmu/8000");
        Attribute attr3 = sdpFactory.createAttribute("recvonly", null);
        attrs1.addElement(attr1);
        attrs1.addElement(attr2);
        attrs1.addElement(attr3);
        
        md1.setAttributes(attrs1);
        mds.addElement(md1);
        sd.setMediaDescriptions(mds);
        
        sdpData = sd.toString();
      }
      catch (SdpException ex)
      {
        System.err.print(ex.toString());
      }
      return sdpData;
    }
    
    private static void SDPParser2(String sdpData)
    	    throws ParseException, SdpException
    	  {
    	    SDPAnnounceParser parser = new SDPAnnounceParser(sdpData);
    	    SessionDescriptionImpl sessiondescription = parser.parse();
    	    
    	    Vector attrs = sessiondescription.getAttributes(false);
    	    if (attrs != null)
    	    {
    	      Attribute attrib = (Attribute)attrs.get(0);
    	      System.out.println("attrs = " + attrib.getName());
    	    }
    	    MediaDescription md = 
    	      (MediaDescription)sessiondescription.getMediaDescriptions(false).get(0);
    	    
    	//    System.out.println("md attributes " + md.getAttributes(false));
    	    
    	    SessionDescriptionImpl sessiondescription1 = new SDPAnnounceParser(sessiondescription
    	      .toString()).parse();
    	    

    	    new Shootisttest().recordingSocket2(sessiondescription1.getConnection().toString().split("IN IP4 ")[1], md.getMedia().toString().split("m=audio | RTP")[1], md.getAttribute("rtcp"));
    	    System.out.println("Caller IP: " + IPcaller/*sessiondescription1.getConnection().toString().split("IN IP4 ")[1]*/);
    	    System.out.println("Caller RTP port: " + RTPportcaller/*md.getMedia().toString().split("m=audio | RTP")[1]*/);
    	    System.out.println("Caller RTCP port: " + RTCPportcaller/*md.getAttribute("rtcp")*/);
    	  }
   
    
    public int getLocalRTPport()
    {
      return localRtpPort;
    }
    
    public int getLocalRTCPport()
    {
      return localRtcpPort;
    }
    public  void init() {
    	 try
         {
           new Shootisttest().STUNPut();
           new Shootisttest().getlocalIP();
         }
         catch (MessageHeaderParsingException|UtilityException|IOException|MessageAttributeException e)
         {
           ((Throwable) e).printStackTrace();
         }
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
        // implementation.履�??
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
            udpListeningPoint = sipStack.createListeningPoint(localIP,
                    MyPort, "udp");
            sipProvider = sipStack.createSipProvider(udpListeningPoint);
            Shootisttest listener = this;
            sipProvider.addSipListener(listener);
           
            String fromName = "CN";
            String fromSipAddress = "open-ims.test";  
            String toUser = "CN";
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
            ViaHeader viaHeader = headerFactory.createViaHeader(MyAddress,
                    MyPort,
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
			String host = MyAddress;
            //	Header contactH;
			contactH = headerFactory.createHeader("Contact", "<sip:CN@"+MyAddress+":"+MyPort+";transport=udp>;expires=60;+g.oma.sip-im;language=\"en,fr\";+g.3gpp.smsip;+g.oma.sip-im.large-message;audio;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-vs\";+g.3gpp.cs-voice");           
			// contactH = headerFactory.createHeader("Contact","<sip:CN@163.17.21.71:MyPort;transport=udp>;expires=60;+g.oma.sip-im;language=\"en,fr\";+g.3gpp.smsip;+g.oma.sip-im.large-message");
                        request.addHeader(contactH);
            // Create the contact name address.
            SipURI contactURI = addressFactory.createSipURI(fromName, host);
            contactURI.setPort(sipProvider.getListeningPoint(transport)
                    .getPort());

            Address contactAddress = addressFactory.createAddress(contactURI);
      /*            
            // Add the contact address.添�?�聯繫人?��????
            contactAddress.setDisplayName(fromName);

            contactHeader = headerFactory.createContactHeader(contactAddress);
            request.addHeader(contactHeader);
        */
           
            // You can add extension headers of your own making��
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

            // Supported?��???
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
            request.addHeader(secClient);

            
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
            if (Request.INVITE.equals("INVITE")) {
                request.setContent(SDPsetting(), contentTypeHeader);
              }
            
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
            inviteTidClient = sipProvider.getNewClientTransaction(request);       
            // send the request out.
            inviteTidClient.sendRequest();
          
            dialogCall = inviteTidClient.getDialog();

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
	      String username = "CN@open-ims.test";
	      String password = "CN";
	      
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
    


    public void processIOException(IOExceptionEvent exceptionEvent) {
        System.out.println("IOException happened for "
                + exceptionEvent.getHost() + " port = "
                + exceptionEvent.getPort());

    }

    public void processTransactionTerminated(
            TransactionTerminatedEvent transactionTerminatedEvent) {
        System.out.println("Transaction terminated event recieved");
    }

    public void processDialogTerminated(
            DialogTerminatedEvent dialogTerminatedEvent) {
        System.out.println("dialogTerminatedEvent");

    }
   

	public void SendBye() {
		// TODO Auto-generated method stub
		try
	    {
			 Request byeRequest = dialogCall.createRequest("BYE");
		      ClientTransaction ct = sipProvider.getNewClientTransaction(byeRequest);
		      dialogCall.sendRequest(ct);
	    }
	    catch (SipException e)
	    {
	      e.printStackTrace();
	    }
	}
   
}