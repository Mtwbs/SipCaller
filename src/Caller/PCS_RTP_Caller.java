package Caller;



import de.javawi.jstun.attribute.MappedAddress;
import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.test.BindingLifetimeTest;
import de.javawi.jstun.util.UtilityException;
import auth.GreetingServer;
import auth.Shootisttest;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioFormat.Encoding;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.Port;
import javax.sound.sampled.Port.Info;
import javax.sound.sampled.SourceDataLine;
import javax.sound.sampled.TargetDataLine;
import javax.swing.JOptionPane;


import jlibrtp.DataFrame;
import jlibrtp.Participant;
import jlibrtp.Participant2;
import jlibrtp.RTPAppIntf;
import jlibrtp.RTPSession;

public class PCS_RTP_Caller
  implements RTPAppIntf
{
  private static BindingLifetimeTest getstun = new BindingLifetimeTest("163.17.21.221", 3478);
  private static String remoteIP = "";
  private static int remoteRtpPort = 0;
  
  
  
  private static int remoteRtcpPort = 0;
  public static int localRtpPort = 0;
  public static int localRtcpPort = 0;
  private static String localIP;
  private static String Parti_Caller;
 
  
  private void UDPping(int srcPORT, int dstPORT)
    throws IOException
  {
    DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(srcPORT));
    InetAddress IPAddress = InetAddress.getByName(remoteIP);
    
    byte[] sendData = new byte[1024];
    
    String sentence = "UDP ping";
    sendData = sentence.getBytes();
    
    DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, dstPORT);
    clientSocket.send(sendPacket);
    try {
		Thread.sleep(5000);
	} catch (InterruptedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    clientSocket.close();
  }
  
  private Shootisttest test = new Shootisttest();
   
  private void STUNPut()
		    throws SocketException, UnknownHostException, MessageAttributeParsingException, MessageHeaderParsingException, UtilityException, IOException, MessageAttributeException
		  {
		    System.out.println(localRtpPort + " SAME111111@@@@@@@");
		    getstun.test2(localRtpPort);
		    localRtpPort = getstun.ma.getPort();
		    
		    System.out.println(localRtpPort + " SAME222222@@@@@@@");
		    
		    System.out.println(localRtcpPort + " SAME111111@@@@@@@");
		    getstun.test2(localRtcpPort);
		    localRtcpPort = getstun.ma.getPort();
		    
		    System.out.println(localRtcpPort + " SAME222222@@@@@@@");
		  }
  private void STUNPut2()
		    throws SocketException, UnknownHostException, MessageAttributeParsingException, MessageHeaderParsingException, UtilityException, IOException, MessageAttributeException
		  {
		    System.out.println(localRtpPort + " SAME111111@@@@@@@");
		    getstun.test2(localRtpPort);
		    localRtpPort = getstun.ma.getPort();
		    
		    System.out.println(localRtpPort + " SAME222222@@@@@@@");
		    
		    System.out.println(localRtcpPort + " SAME111111@@@@@@@");
		    getstun.test2(localRtcpPort);
		    localRtcpPort = getstun.ma.getPort();
		    
		    System.out.println(localRtcpPort + " SAME222222@@@@@@@");
		  }
  
  public void Port()
  {
    remoteIP = this.test.getCalleeIP();
    remoteRtpPort = Integer.valueOf(this.test.getCalleeRTPport()).intValue();
    remoteRtcpPort = Integer.valueOf(this.test.getCalleeRTCPport()).intValue();
    localRtpPort = this.test.getLocalRTPport();
    localRtcpPort = this.test.getLocalRTCPport();
    System.out.println("remote IP: " + remoteIP);
    System.out.println("remote RTP port: " + remoteRtpPort);
    System.out.println("remote RTCP port: " + remoteRtcpPort);
    System.out.println("Local RTP port: " + localRtpPort);
    System.out.println("Local RTCP port: " + localRtcpPort);
    /*
    try {
		UDPping(localRtpPort,remoteRtpPort);
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	*/
  }
  
  public void Port2()
  {
    remoteIP = this.test.getCallerIP();
    remoteRtpPort = Integer.valueOf(this.test.getCallerRTPport()).intValue();
    remoteRtcpPort = Integer.valueOf(this.test.getCallerRTCPport()).intValue();
    localRtpPort = this.test.getLocalRTPport();
    localRtcpPort = this.test.getLocalRTCPport();
    System.out.println(" Caller remote IP: " + remoteIP);
    System.out.println(" Caller remote Rtp Port: " + remoteRtpPort);
    System.out.println(" Caller remote Rtcp Port: " + remoteRtcpPort);
    System.out.println(" Callee local Rtp Port: " + localRtpPort);
    System.out.println(" Callee local Rtcp Port: " + localRtcpPort);
   /*
    try {
		UDPping(localRtpPort,remoteRtpPort);
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	*/
  }
  
  private final int BUFFER_SIZE = 1024;
  private static AudioFormat format;
  public static TargetDataLine microphone;
  public static SourceDataLine speaker;
  public static RTPSession rtpSession;
  private DatagramSocket rtpSocket;
  private DatagramSocket rtcpSocket;
  public static boolean isRegistered = false;
  public static boolean isReceived = false;
  public static boolean isRegistered2 = false;
  public static boolean isReceived2 = false;
  public static PCS_UI ui;
  public static boolean SIPVoiceFlag;
  
  public void checkDeviceIsOK()
  {
    if (!AudioSystem.isLineSupported(Port.Info.MICROPHONE))
    {
      System.out.println("Error! Please make sure that your microphone is available!");
      JOptionPane.showMessageDialog(null, "Error! Please make sure that your microphone is available!");
      System.exit(-1);
    }
    if ((!AudioSystem.isLineSupported(Port.Info.SPEAKER)) && (!AudioSystem.isLineSupported(Port.Info.HEADPHONE)))
    {
      System.out.println("Error! Please make sure that your speaker or headphone is available!");
      JOptionPane.showMessageDialog(null, "Error! Please make sure that your speaker or headphone is available!");
      System.exit(-1);
    }
  }
  
  public void setAudioFormat()
  {
    AudioFormat.Encoding encoding = AudioFormat.Encoding.PCM_SIGNED;
    float rate = 8000.0F;
    int channels = 1;
    int sampleSize = 16;
    boolean bigEndian = false;
    
    format = new AudioFormat(encoding, rate, sampleSize, channels, sampleSize / 8 * channels, rate, bigEndian);
  }
  
  public void initRecorder()
  {
    try
    {
      microphone = AudioSystem.getTargetDataLine(format);
      microphone.open();
      microphone.start();
    }
    catch (LineUnavailableException e)
    {
      e.printStackTrace();
      System.exit(-1);
    }
  }
  
  public void initPlayer()
  {
    try
    {
      speaker = AudioSystem.getSourceDataLine(format);
      speaker.open();
      speaker.start();
    }
    catch (LineUnavailableException e)
    {
      e.printStackTrace();
      System.exit(-1);
    }
  }
  
  public void setCallerUI(String title)
  {
    ui = new PCS_UI(title);
    

    WindowAdapter adapter = new WindowAdapter()
    {
      public void windowClosing(WindowEvent e)
      {
        if (PCS_RTP_Caller.isRegistered)
        {
          Enumeration<Participant> list = PCS_RTP_Caller.rtpSession.getParticipants();
          while (list.hasMoreElements())
          {
            Participant p = (Participant)list.nextElement();
            PCS_RTP_Caller.rtpSession.removeParticipant(p);
          }
          PCS_RTP_Caller.rtpSession.endSession();
        }
        System.out.println("Window is closed!");
        System.exit(0);
      }
    };
    ActionListener listener = new ActionListener()
    {
      public void actionPerformed(ActionEvent arg0)
      {
        if (PCS_RTP_Caller.ui.getButtonText() == "Dial")
        {
          PCS_RTP_Caller.this.test.SendInvite();           
          PCS_RTP_Caller.ui.setButtonText("End");
          PCS_RTP_Caller.ui.setStateText("Running");
        }
        else
        {
          PCS_RTP_Caller.this.test.SendBye();
          PCS_RTP_Caller.this.EndSession();
        }
      }
    };
    ui.setWindowListener(adapter);
    ui.getClass();ui.setWindowLocation(ui.getWindowLocation().x - 400, ui.getWindowLocation().y);
    ui.setButtonText("Dial");
    ui.setButtonActionListener(listener);
  }
  
  public void EndSession()
  {
    if (isRegistered)
    {
      Enumeration<Participant> list = rtpSession.getParticipants();
      while (list.hasMoreElements())
      {
        Participant p = (Participant)list.nextElement();
        rtpSession.removeParticipant(p);
      }
      isReceived = false;
      isRegistered = false;
      rtpSession.endSession();
      rtpSession = null;
      
      Shootisttest.inPhoneCallProcess = false;
      Shootisttest.inReferProcess = false;
    }
    ui.setButtonText("Dial");
    ui.setStateText("Stopped");
  }
  
  public void EndSession2()
  {
    if (isRegistered2)
    {
      Enumeration<Participant> list = rtpSession.getParticipants();
      while (list.hasMoreElements())
      {
        Participant p = (Participant)list.nextElement();
        rtpSession.removeParticipant(p);
      }
      this.isReceived2 = false;
      isRegistered2 = false;
      rtpSession.endSession();
      rtpSession = null;
    }
    ui.setButtonText("Answer");
    ui.setStateText("Stopped");
  }
  
  public void addNewParticipant(String networkAddress, int dstRtpPort, int dstRtcpPort, int srcRtpPort, int srcRtcpPort)
  {
	  try
	    {
	      new PCS_RTP_Caller().STUNPut();
	    }
	    catch (MessageHeaderParsingException|UtilityException|IOException|MessageAttributeException e1)
	    {
	      e1.printStackTrace();
	    }
  
    try
    {
      this.rtpSocket = new DatagramSocket(srcRtpPort);
      this.rtcpSocket = new DatagramSocket(srcRtcpPort);
      this.rtpSocket.setReuseAddress(true);
      this.rtcpSocket.setReuseAddress(true);
    }
    catch (Exception e)
    {
      System.out.println("RTPSession failed to obtain port");
      JOptionPane.showMessageDialog(null, "RTPSession failed to obtain port");
      System.exit(-1);
    }
    rtpSession = new RTPSession(this.rtpSocket, this.rtcpSocket);
    Participant p = new Participant(networkAddress, dstRtpPort, dstRtcpPort);
    rtpSession.addParticipant(p);
    rtpSession.RTPSessionRegister(this, null, null);
    isRegistered = true;
    try
    {
      Thread.sleep(1000L);
    }
    catch (Exception localException1) {}
  }
  
  public void addNewParticipant2(String networkAddress, int dstRtpPort, int dstRtcpPort, int srcRtpPort, int srcRtcpPort)
  {
	
	  try
	    {
	      new PCS_RTP_Caller().STUNPut2();
	    }
	    catch (MessageHeaderParsingException|UtilityException|IOException|MessageAttributeException e1)
	    {
	      e1.printStackTrace();
	    }
	    
    try
    {
      this.rtpSocket = new DatagramSocket(srcRtpPort);
      this.rtcpSocket = new DatagramSocket(srcRtcpPort);
      this.rtpSocket.setReuseAddress(true);
      this.rtcpSocket.setReuseAddress(true);
    }
    catch (Exception e)
    {
      System.out.println("RTPSession failed to obtain port");
      JOptionPane.showMessageDialog(null, "RTPSession failed to obtain port");
      System.exit(-1);
    }
    rtpSession = new RTPSession(this.rtpSocket, this.rtcpSocket);
    Participant p = new Participant(networkAddress, dstRtpPort, dstRtcpPort);
    rtpSession.addParticipant(p);
    rtpSession.RTPSessionRegister(this, null, null);
    Parti_Caller = p.toString();
    isRegistered2 = true;
    try
    {
      Thread.sleep(1000L);
    }
    catch (Exception localException1) {}
  }
  
  public void startTalking()
  {
    Thread thread = new Thread(new Runnable()
    {
      public void run()
      {
        System.out.println("Caller start to talk");
        byte[] data = new byte[1024];
        int packetCount = 0;
        int nBytesRead = 0;
        while (nBytesRead != -1)
        {
          nBytesRead = PCS_RTP_Caller.microphone.read(data, 0, data.length);
          if (!PCS_RTP_Caller.isRegistered) {
            nBytesRead = -1;
          }
          if (nBytesRead >= 0)
          {
            PCS_RTP_Caller.rtpSession.sendData(data);
            packetCount++;
            if (packetCount == 100)
            {
              Enumeration<Participant> iter = PCS_RTP_Caller.rtpSession.getParticipants();
              Participant p = null;
              while (iter.hasMoreElements())
              {
                p = (Participant)iter.nextElement();
                
                String name = "TEST";
                byte[] nameBytes = name.getBytes();
                String str = "abcd";
                byte[] dataBytes = str.getBytes();
                
                int ret = PCS_RTP_Caller.rtpSession.sendRTCPAppPacket(p.getSSRC(), 0, nameBytes, dataBytes);
                System.out.println("!!!!!!!!!!!! ADDED APPLICATION SPECIFIC " + ret);
              }
              if (p == null) {
                System.out.println("No participant with SSRC available :(");
              }
            }
          }
        }
      }
    });
    thread.start();
  }
  
 
  public void startTalking2()
  {
    Thread thread = new Thread(new Runnable()
    {
      public void run()
      {
        System.out.println("Callee start to talk");
        byte[] data = new byte[1024];
        int packetCount = 0;
        int nBytesRead = 0;
        while (nBytesRead != -1)
        {
          nBytesRead = PCS_RTP_Caller.microphone.read(data, 0, data.length);
          if (!PCS_RTP_Caller.isRegistered2) {
            nBytesRead = -1;
          }
          if (nBytesRead >= 0)
          {
            PCS_RTP_Caller.rtpSession.sendData(data);
            packetCount++;
            if (packetCount == 100)
            {
              Enumeration<Participant> iter = PCS_RTP_Caller.rtpSession.getParticipants();
              Participant p = null;
              while (iter.hasMoreElements())
              {
                p = (Participant)iter.nextElement();
                
                String name = "TEST";
                byte[] nameBytes = name.getBytes();
                String str = "abcd";
                byte[] dataBytes = str.getBytes();
                
                int ret = PCS_RTP_Caller.rtpSession.sendRTCPAppPacket(p.getSSRC(), 0, nameBytes, dataBytes);
                System.out.println("!!!!!!!!!!!! ADDED APPLICATION SPECIFIC " + ret);
              }
              if (p == null) {
                System.out.println("No participant with SSRC available :(");
              }
            }
          }
        }
      }
    });
    thread.start();
  }
  static boolean flag = true;
  static boolean flag2 = true;
  public void receiveData(DataFrame frame, Participant participant)
  {
	 
	  if (flag) {

		  flag = false;
		  System.out.println("-------------------------------------------------------------------------------------------------");
		  //写要执行的代码
		  System.out.println("speaker++++++++++"+speaker);	
		  }
		
	  
    if (speaker != null ) {
      if (speaker != null )
    	  
      {
        byte[] data = frame.getConcatenatedData();
        speaker.write(data, 0, data.length);
        if (!isReceived)
        {
          System.out.println("Received callee's data");
          isReceived = true;
        }
       
      }
    }
    
    
    if (flag2) {

		  flag2 = false;
		  System.out.println("-------------------------------------------------------------------------------------------------");
		  //写要执行的代码
		  System.out.println("participant.toString()+++++"+participant.toString());
		  System.out.println("participant.toString()Parti_Caller+++++"+Parti_Caller);
		  System.out.println("participant.toString()isRegistered+++++"+isRegistered2);
		  System.out.println("speaker++++++++++"+speaker);	
		  }
		 

    
    
    if ((participant.toString().equals(Parti_Caller)) && (isRegistered2))
    {
    //	System.out.println("participant.toString()Parti_Caller+++++"+Parti_Caller);	
   /* 
    	byte[] data = frame.getConcatenatedData();
      
      speaker.write(data, 0, data.length);
   */ 
      if (!this.isReceived2)
      {
        System.out.println("Received caller's data");
        this.isReceived2 = true;
      }
    }
    
  }
  
  public void userEvent(int type, Participant[] participant) {}
  
  public int frameSize(int payloadType)
  {
    return 1;
  }
  
  public void Media()
  {
    if ((remoteIP.equals("0.0.0.0")) || (remoteRtpPort == 0) || (remoteRtcpPort == 0) || (localRtpPort == 0) || (localRtcpPort == 0))
    {
      ui.setStateText("Wrong IP and Port!");
      return;
    }
    addNewParticipant(remoteIP, remoteRtpPort, remoteRtcpPort, localRtpPort, localRtcpPort);
    startTalking();
  }
  public void Media2()
  {
    if ((remoteIP.equals("0.0.0.0")) || (remoteRtpPort == 0) || (remoteRtcpPort == 0) || (localRtpPort == 0) || (localRtcpPort == 0))
    {
      ui.setStateText("Wrong IP and Port!");
      return;
    }
    addNewParticipant2(remoteIP, remoteRtpPort, remoteRtcpPort, localRtpPort, localRtcpPort);
    startTalking2();
  }
  
 
 
  
  public static void main(String [] args)
  {
	 
	
    new Shootisttest().init();
    
    PCS_RTP_Caller obj = new PCS_RTP_Caller();
    obj.setCallerUI("This is Caller!");
    obj.setAudioFormat();
    obj.checkDeviceIsOK();
    obj.initRecorder();
    obj.initPlayer();
  //  new PCS_RTP_Callee().Callee();
  }
  
}
