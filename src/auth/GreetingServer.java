package auth;

// File Name GreetingServer.java
import Caller.PCS_RTP_Caller;
import java.net.*;
import java.io.*;

public class GreetingServer extends Thread
{
   private ServerSocket serverSocket;
   
   public GreetingServer(int port) throws IOException
   {
      serverSocket = new ServerSocket(port);
      serverSocket.setSoTimeout(100000);
   }

   public void run()
   {
     
         try
         {
            System.out.println("Waiting for client on port " +
            serverSocket.getLocalPort() + "...");
            Socket server = serverSocket.accept();
            System.out.println("Just connected to "
                  + server.getRemoteSocketAddress());
            DataInputStream in =
                  new DataInputStream(server.getInputStream());
            System.out.println(in.readUTF());
            DataOutputStream out =
                 new DataOutputStream(server.getOutputStream());
            out.writeUTF("Thank you for connecting to "
              + server.getLocalSocketAddress() + "Goodbye!");
            //server.close();
          //  new PCS_RTP_Caller().main2();
            System.out.println("Waitinxcvxcvxcvxc.");
         }catch(SocketTimeoutException s)
         {
            System.out.println("Socket timed out!");
          //  break;
         }catch(IOException e)
         {
            e.printStackTrace();
         //   break;
         }
      
   }
   public static void main(String [] args)
   {
      int port = 51982;
      try
      {
    	  
         Thread t = new GreetingServer(port);
         t.start();
         
      }catch(IOException e)
      {
         e.printStackTrace();
      }
   }
}