package de.javawi.jstun.test;
import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;

import de.javawi.jstun.attribute.MessageAttributeException;
import de.javawi.jstun.attribute.MessageAttributeParsingException;
import de.javawi.jstun.header.MessageHeaderParsingException;
import de.javawi.jstun.test.BindingLifetimeTest;
import de.javawi.jstun.util.UtilityException;
public class STUN {

	public static void stun() throws SocketException, UnknownHostException, MessageAttributeParsingException, MessageHeaderParsingException, UtilityException, IOException, MessageAttributeException {
		// TODO Auto-generated method stub
		BindingLifetimeTest stun=new BindingLifetimeTest("163.17.21.188", 3478);
		stun.test();
		System.out.println(stun.ma.getAddress());
		
		//String[] tokens = str.split(":")
		
	}
}
