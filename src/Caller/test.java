package Caller;
/**
 * PCS RTP Project
 * Copyright (C) 2013 QQting ^_<b
 * Wireless Mobile Networking Laboratory
 * National Tsing Hua University, Taiwan
 */

import auth.Shootist;
import auth.Shootisttest;

import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.test.BindingLifetimeTest;
import de.javawi.jstun.util.UtilityException;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.PrintStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.Port;
import javax.sound.sampled.SourceDataLine;
import javax.sound.sampled.TargetDataLine;
import javax.swing.JOptionPane;
import jlibrtp.DataFrame;
import jlibrtp.Participant;
import jlibrtp.RTPAppIntf;
import jlibrtp.RTPSession;


public class test implements RTPAppIntf {
	
	// for Java Audio
	private final int BUFFER_SIZE = 1024;
	private AudioFormat format;
	private TargetDataLine microphone;
	private SourceDataLine speaker; // also used as headphone
	
	// for RTP
	private static RTPSession rtpSession;
	private DatagramSocket rtpSocket;
	private DatagramSocket rtcpSocket;
	private boolean isRegistered = false;
	private boolean isReceived = false;
	
	// for Caller UI
	private static  PCS_UI ui;
	
	//Shootist
	private Shootist sipstart=new Shootist();

	
	
	
	  private static String remoteIP = "";
	  private static int remoteRtpPort = 0;
	  private static int remoteRtcpPort = 0;
	  public static int localRtpPort = 0;
	  public static int localRtcpPort = 0;
	  private static String localIP;
/*	public PCS_RTP_Caller() {
		// PCS_RTP_Caller constructor
	}
*/	

	  
	
	
	 public void Port()
	  {
		
	    remoteIP = new Shootisttest().getCalleeIP();
	    remoteRtpPort = Integer.valueOf(new Shootisttest().getCalleeRTPport()).intValue();
	    remoteRtcpPort = Integer.valueOf(new Shootisttest().getCalleeRTCPport()).intValue();
	    localRtpPort = new Shootisttest().getLocalRTPport();
	    localRtcpPort = new Shootisttest().getLocalRTCPport();
	    System.out.println("remote IP: " + remoteIP);
	    System.out.println("remote RTP port: " + remoteRtpPort);
	    System.out.println("remote RTCP port: " + remoteRtcpPort);
	    System.out.println("Local RTP port: " + localRtpPort);
	    System.out.println("Local RTCP port: " + localRtcpPort);
	  }
	
	public void checkDeviceIsOK() {
		if(!AudioSystem.isLineSupported(Port.Info.MICROPHONE)) {
			System.out.println("Error! Please make sure that your microphone is available!");
			JOptionPane.showMessageDialog(null, "Error! Please make sure that your microphone is available!");
			System.exit(-1);
		}
		if(!AudioSystem.isLineSupported(Port.Info.SPEAKER) && !AudioSystem.isLineSupported(Port.Info.HEADPHONE)) {
			System.out.println("Error! Please make sure that your speaker or headphone is available!");
			JOptionPane.showMessageDialog(null, "Error! Please make sure that your speaker or headphone is available!");
			System.exit(-1);
		}
	}
	
	public void setAudioFormat() {
		AudioFormat.Encoding encoding = AudioFormat.Encoding.PCM_SIGNED;
        float rate = 8000.0f;
        int channels = 1;
        int sampleSize = 16;
        boolean bigEndian = false;
		
		format = new AudioFormat(encoding, rate, sampleSize, channels, (sampleSize / 8) * channels, rate, bigEndian);
	}
	
	public void initRecorder() {
		try {
			microphone = AudioSystem.getTargetDataLine(format);
			microphone.open();
			microphone.start();		
		} catch (LineUnavailableException e) {
			e.printStackTrace();
			System.exit(-1);
		}
	}
	
	public void initPlayer() {
		//TODO 1. initialize your speaker
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
	
	public void setCallerUI(String title) {
		ui = new PCS_UI(title);
		
		//set the action when the window is closing
		WindowAdapter adapter = new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				if(isRegistered) {
					Enumeration<Participant> list = rtpSession.getParticipants();
					while(list.hasMoreElements()) {
						Participant p = list.nextElement(); 
						rtpSession.removeParticipant(p);
					}
					rtpSession.endSession();
				}
				System.out.println("Window is closed!");
				System.exit(0);
			}
		};

		//set the action of button
		ActionListener listener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				if(ui.getButtonText() == "Cancel") {		
				}
				
				if(ui.getButtonText() == "Dial") {
					//new Shootist().SendInvite();	
					new Shootisttest().SendInvite();
			/*		
			        PCS_RTP_Caller.ui.setStateText("InCall");
			        PCS_RTP_Caller.ui.setButtonText("Bye");
			*/	
				/*
					String remoteIP = ui.getRemoteIP();
					int remoteRtpPort = ui.getRemoteRtpPort();
					int remoteRtcpPort = ui.getRemoteRtcpPort();
					int localRtpPort = ui.getLocalRtpPort();
					int localRtcpPort = ui.getLocalRtcpPort();
					if(remoteIP.equals("0.0.0.0") || remoteRtpPort == 0 || remoteRtcpPort == 0 || localRtpPort == 0 || localRtcpPort == 0) {
						ui.setStateText("Wrong IP and Port!");
						System.out.println("* Callee Attribute list: IP: " + remoteIP);
					    System.out.println("* Callee Attribute list: RTP port: " + remoteRtpPort);
					    System.out.println("* Callee Attribute list: RTCP port: " + remoteRtcpPort);
					    System.out.println("\n* Caller Attribute list: RTP port: " + localRtpPort);
					    System.out.println("* Caller Attribute list: RTCP port: " + localRtcpPort);
						return;
					}
					addNewParticipant(remoteIP, remoteRtpPort, remoteRtcpPort, localRtpPort, localRtcpPort);
					
					
					startTalking();
				*/	ui.setButtonText("End");
					ui.setStateText("Running");
					
					
				}else {
					if(isRegistered) {						
						Enumeration<Participant> list = rtpSession.getParticipants();
						while(list.hasMoreElements()) {
							Participant p = list.nextElement(); 
							rtpSession.removeParticipant(p);
						}
						isReceived = false;
						isRegistered = false;
						rtpSession.endSession();
						rtpSession = null;
					}
					ui.setButtonText("Dial");
					ui.setStateText("Stopped");
				}
			}
		};
		
		ui.setWindowListener(adapter);
		ui.setWindowLocation(ui.getWindowLocation().x - ui.width, ui.getWindowLocation().y);
		ui.setButtonText("Dial");
		ui.setButtonActionListener(listener);
	} //end setCallerUI()
	private static BindingLifetimeTest getstun = new BindingLifetimeTest("163.17.21.188", 3478);
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
	public void addNewParticipant(String networkAddress, int dstRtpPort, int dstRtcpPort, int srcRtpPort, int srcRtcpPort) {
	/*	try
	    {
	      new PCS_RTP_Caller().STUNPut();
	    }
	    catch (MessageHeaderParsingException|UtilityException|IOException|MessageAttributeException e1)
	    {
	      e1.printStackTrace();
	    }*/
		try {
			rtpSocket = new DatagramSocket(srcRtpPort);
			rtcpSocket = new DatagramSocket(srcRtcpPort);
			rtpSocket.setReuseAddress(true);
			rtcpSocket.setReuseAddress(true);
		} catch (Exception e) {
			System.out.println("RTPSession failed to obtain port");
			JOptionPane.showMessageDialog(null, "RTPSession failed to obtain port");
			System.exit(-1);
		}
		
		rtpSession = new RTPSession(rtpSocket, rtcpSocket);
		Participant p = new Participant(networkAddress, dstRtpPort, dstRtcpPort);
		rtpSession.addParticipant(p);
		rtpSession.RTPSessionRegister(this, null, null);		
		isRegistered = true;
		
		// Wait 1000 ms, because of the initial RTCP wait
		try{ Thread.sleep(1000); } catch(Exception e) {}
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

	  public void startTalking() {
			
			Thread thread = new Thread(new Runnable() {
				@Override
				public void run() {
					System.out.println("Caller start to talk");
					byte[] data = new byte[BUFFER_SIZE];
					int packetCount = 0;
					int nBytesRead = 0;
					while (nBytesRead != -1) {
						nBytesRead = microphone.read(data, 0, data.length);
						if(!isRegistered)
							nBytesRead = -1;
						if (nBytesRead >= 0) {
							rtpSession.sendData(data);
							packetCount++;
							
							if (packetCount == 100) {
								Enumeration<Participant> iter = rtpSession.getParticipants();
								Participant p = null;
								while (iter.hasMoreElements()) {
									p = iter.nextElement();

									String name = "TEST";
									byte[] nameBytes = name.getBytes();
									String str = "abcd";
									byte[] dataBytes = str.getBytes();

									int ret = rtpSession.sendRTCPAppPacket(p.getSSRC(), 0, nameBytes, dataBytes);
									System.out.println("!!!!!!!!!!!! ADDED APPLICATION SPECIFIC "+ ret);
									continue;
								}
								if (p == null)
									System.out.println("No participant with SSRC available :(");
							}
						}
					} //end while
				}
			});
			
			thread.start();
		} //end startTalking()
	@Override
	public void userEvent(int type, Participant[] participant) {
		//do nothing
		
	}

	@Override
	public int frameSize(int payloadType) {
		return 1;
	}
	
	
	public static void main(String[] args) throws SocketException, UnknownHostException, MessageAttributeParsingException, MessageHeaderParsingException, UtilityException, IOException, MessageAttributeException {
		
		//new Shootist().sipstart();
		new Shootisttest().init();
		PCS_RTP_Caller obj = new PCS_RTP_Caller();

		obj.checkDeviceIsOK();	
		obj.setAudioFormat();
		obj.initRecorder();
		obj.initPlayer();
		obj.setCallerUI("This is Caller!");
		
	}
	@Override
	public void receiveData(DataFrame frame, Participant participant) {
		if(speaker != null) {
			byte[] data = frame.getConcatenatedData();
			speaker.write(data, 0, data.length);
			if(!isReceived) {
				System.out.println("Received callee's data");
				isReceived = true;
			}
		}
	}
	




} //end class
