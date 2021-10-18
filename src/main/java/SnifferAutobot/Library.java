package SnifferAutobot;

import java.io.Console;
import java.util.HashMap;
import java.util.Map;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import com.sun.jna.Platform;

// step 1: Install Npcap with WinPcap Compatible Mode on.
public class Library {
	// Map<Short, List<IpV4Packet>> ipV4Packets = new HashMap<Short, List<IpV4Packet>>();
	Map<Short, Packet> originalPackets = new HashMap<Short, Packet>();
	
	private static final String COUNT_KEY = Library.class.getName() + ".count";
	private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);
	
	private static final String SNAPLEN_KEY = Library.class.getName() + ".snaplen";
	
	private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
	
	private static final String READ_TIMEOUT_KEY = Library.class.getName() + ".readTimeout";
	private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]
	  
	private static final String BUFFER_SIZE_KEY = Library.class.getName() + ".bufferSize";
	private static final int BUFFER_SIZE =
	      Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

	private static final String TIMESTAMP_PRECISION_NANO_KEY =
			  Library.class.getName() + ".timestampPrecision.nano";
	private static final boolean TIMESTAMP_PRECISION_NANO =
	      Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);
	
    public static void main(String[] args) throws Exception {
    	 PcapNetworkInterface nif;
    	 
    	 System.out.println("test");
    	 
    	 nif = new NifSelector().selectNetworkInterface();
    	 
    	 
    	 System.out.println(nif.getName() + "(" + nif.getDescription() + ")");
    	 
	    for (PcapAddress addr : nif.getAddresses()) {
	      if (addr.getAddress() != null) {
	        System.out.println("IP address: " + addr.getAddress());
	      }
	    }
	    System.out.println("");
	 
	    PcapHandle.Builder phb =
	            new PcapHandle.Builder(nif.getName())
	                .snaplen(SNAPLEN)
	                .promiscuousMode(PromiscuousMode.PROMISCUOUS)
	                .timeoutMillis(READ_TIMEOUT)
	                .bufferSize(BUFFER_SIZE);
        if (TIMESTAMP_PRECISION_NANO) {
          phb.timestampPrecision(TimestampPrecision.NANO);
        }
        PcapHandle handle = phb.build();

        handle.setFilter("", BpfCompileMode.OPTIMIZE);

        int num = 0;
        while (true) {
          Packet packet = handle.getNextPacket();
          if (packet == null) {
            continue;
          } else {
            System.out.println(handle.getTimestamp());
            System.out.println(packet);
            num++;
            if (num >= COUNT) {
              break;
            }
          }
        }

        PcapStat ps = handle.getStats();
        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
        if (Platform.isWindows()) {
          System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
        }

        handle.close();
    }
}
