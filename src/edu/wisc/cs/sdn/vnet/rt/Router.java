package edu.wisc.cs.sdn.vnet.rt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/** List of packet queues waiting on ARP requests */
	private Map<Integer, Queue<IPacket>> packetQueue;
	
	/** Keeps track of the ARP requests for a given address. */
	private Map<Integer, Integer> arpRequestCounts;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.packetQueue = new HashMap<Integer, Queue<IPacket>>();
		this.arpRequestCounts = new HashMap<Integer, Integer>();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		switch(etherPacket.getEtherType())
		{
			case Ethernet.TYPE_IPv4:
				this.handleIpPacket(etherPacket, inIface);
			break;
			case Ethernet.TYPE_ARP:
				this.handeArpPacket(etherPacket, inIface);
			break;
		}
		
		/* Send ARP Requests */
		for (Entry<Integer, Queue<IPacket>> set : packetQueue.entrySet()) {
			
			int ip = set.getKey();
			Queue<IPacket> queue = set.getValue();
			
			if (queue.size() > 0) {
				
				RouteEntry route = this.routeTable.lookup(ip);
							
				if (arpRequestCounts.get(ip) <= 3) {
	        		generateArpRequest(ip,route.getInterface());
	        	} else {
	        		Ethernet ether = ((Ethernet) queue.peek());
	        		this.sendICMP(ether, route.getInterface(), 3, 1);
	        		arpRequestCounts.remove(ip);
	        		packetQueue.remove(ip);
	        	}
			}
		}
		
	}
	
	/**
	 * Handles ARP requests
	 * 
	 * @param sourcePacket
	 * @param inIface
	 */
	private void handeArpPacket(Ethernet sourcePacket, Iface inIface) {
		
		ARP arpPacket = (ARP)sourcePacket.getPayload();
		MACAddress mac = new MACAddress(arpPacket.getTargetHardwareAddress());
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		int senderIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
		
		if (arpPacket.getOpCode() == ARP.OP_REPLY) {
			
			arpCache.insert(mac, targetIp);
			
			if (packetQueue.containsKey(targetIp)) {
				
				for (IPacket packet : packetQueue.get(targetIp)) {
					
					Ethernet ether = (Ethernet) packet;
					ether.setDestinationMACAddress(mac.toBytes());
					this.sendPacket((Ethernet) packet, inIface);
				}
				
				packetQueue.remove(targetIp);
				arpRequestCounts.remove(targetIp);
				return;
			}
		}
		
		if (arpPacket.getOpCode() != ARP.OP_REQUEST) {
			return;
		}	
		
		if (targetIp != inIface.getIpAddress()) {
			return;
		}
		
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();
		
    	ether.setEtherType(Ethernet.TYPE_ARP);
    	ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
    	ether.setDestinationMACAddress(sourcePacket.getSourceMACAddress());
    	ether.setPayload(arp);
    	
    	arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
    	arp.setProtocolType(ARP.PROTO_TYPE_IP);
    	arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
    	arp.setProtocolAddressLength((byte) 4);
    	arp.setOpCode(ARP.OP_REPLY);
    	arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
    	arp.setSenderProtocolAddress(inIface.getIpAddress());
    	arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
    	arp.setTargetProtocolAddress(senderIp);
    	
    	this.sendPacket(ether, inIface);
	}
	
	private void generateArpRequest(int requestAddress, Iface inIface) {
		
		if (arpRequestCounts.get(requestAddress).intValue() > 3) {
			
			throw new RuntimeException("ARP Request Exceeded Amount");
		}
		
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();
		
    	ether.setEtherType(Ethernet.TYPE_ARP);
    	ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
    	ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
    	ether.setPayload(arp);
    	
    	arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
    	arp.setProtocolType(ARP.PROTO_TYPE_IP);
    	arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
    	arp.setProtocolAddressLength((byte) 4);
    	arp.setOpCode(ARP.OP_REQUEST);
    	arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
    	arp.setSenderProtocolAddress(inIface.getIpAddress());
    	ByteBuffer b = ByteBuffer.allocate(Ethernet.DATALAYER_ADDRESS_LENGTH);
    	b.putInt(0);
    	arp.setTargetHardwareAddress(b.array());
    	arp.setTargetProtocolAddress(requestAddress);
    	
    	this.sendPacket(ether, inIface);
    	arpRequestCounts.put(requestAddress, (arpRequestCounts.get(requestAddress).intValue() + 1));
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        { 
        	this.sendICMP(etherPacket, inIface, 11, 0);
        	return;
        }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{
        		if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP || ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
        			
        			this.sendICMP(etherPacket, inIface, 3, 3);
        			
        		} else {
        			
        			if ( ((ICMP) ipPacket.getPayload()).getIcmpType() == 8) {
        				
        				this.sendEcho(etherPacket, inIface, 0, 0);
        			}
        		}
        		return;
        	}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched
        if (null == bestMatch)
        {
        	this.sendICMP(etherPacket, inIface, 3, 0);
        	return;
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        {
        	this.addPacket(nextHop, etherPacket);
        	
        	if (arpRequestCounts.get(nextHop) <= 3) {
        		generateArpRequest(nextHop,inIface);
        	} else {
        		this.sendICMP(etherPacket, inIface, 3, 1);
        		arpRequestCounts.remove(nextHop);
        		packetQueue.remove(nextHop);
        	}
        	
        	return;
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
    
    /**
     * Sends an ICMP packet with the specified type and code.
     * 
     * @param type
     * @param code
     */
    private void sendICMP(Ethernet failedEtherPacket, Iface iface, int type, int code) {
    	
    	IPv4 ip = new IPv4();
    	ICMP icmp = new ICMP();
    	Data data = new Data();
    	
    	IPv4 failedIpPacket = (IPv4) failedEtherPacket.getPayload();
    	
    	Ethernet ether = new Ethernet();
    	ether.setEtherType(Ethernet.TYPE_IPv4);
    	
    	
    	/* Flip Source/Dest To Reply Back */
    	ether.setSourceMACAddress(iface.getMacAddress().toBytes());
    	int sourceAddress = failedIpPacket.getSourceAddress();
    	RouteEntry bestMatch = this.routeTable.lookup(sourceAddress);
    	// If no entry matched, do nothing
        if (null == bestMatch)
        { 
        	System.out.println("NO ROUTE ENTRY FOUND!");
        	return;
        }
        
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = sourceAddress; }
        
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        {
        	this.addPacket(nextHop, ether);
        	return;
        }
        
    	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
    	ether.setPayload(ip);
    	
    	ip.setTtl((byte) 64);
    	ip.setProtocol(IPv4.PROTOCOL_ICMP);
    	ip.setSourceAddress(iface.getIpAddress());
    	ip.setDestinationAddress( failedIpPacket.getSourceAddress());
    	ip.setPayload(icmp);
    	
    	icmp.setIcmpCode((byte) code);
    	icmp.setIcmpType((byte) type);
    	icmp.setPayload(data);
    	
    	ByteArrayOutputStream byteData = new ByteArrayOutputStream();
    	byte[] padding = {0, 0, 0, 0};
    	try {
			byteData.write(padding);
			byteData.write(failedIpPacket.serialize());
			byte[] ipData = failedIpPacket.getPayload().serialize();
			byteData.write(Arrays.copyOf(ipData, 8));
		} catch (IOException e) {}
    	data.setData(byteData.toByteArray());
    	
    	super.sendPacket(ether, iface);
    }
    
    /**
     * should be sent if your router receives a TCP or UDP packet destined for one of its interfaces. 
     * 
     * @param failedEtherPacket
     * @param iface
     */
    private void sendEcho(Ethernet failedEtherPacket, Iface iface, int type, int code) {
    	
    	IPv4 ip = new IPv4();
    	ICMP icmp = new ICMP();
    	Data data = new Data();
    	
    	IPv4 failedIpPacket = (IPv4) failedEtherPacket.getPayload();
    	
    	Ethernet ether = new Ethernet();
    	ether.setEtherType(Ethernet.TYPE_IPv4);
    	
    	
    	/* Flip Source/Dest To Reply Back */
    	ether.setSourceMACAddress(iface.getMacAddress().toBytes());
    	int sourceAddress = failedIpPacket.getSourceAddress();
    	RouteEntry bestMatch = this.routeTable.lookup(sourceAddress);
    	// If no entry matched, do nothing
        if (null == bestMatch)
        { 
        	System.out.println("NO ROUTE ENTRY FOUND!");
        	return;
        }
        
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = sourceAddress; }
        
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        {
        	System.out.println("NO MAC ENTRY FOUND!");
        	return;
        }
        
    	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
    	ether.setPayload(ip);
    	
    	ip.setTtl((byte) 64);
    	ip.setProtocol(IPv4.PROTOCOL_ICMP);
    	ip.setSourceAddress(failedIpPacket.getDestinationAddress());
    	ip.setDestinationAddress( failedIpPacket.getSourceAddress());
    	ip.setPayload(icmp);
    	
    	icmp.setIcmpCode((byte) code);
    	icmp.setIcmpType((byte) type);
    	icmp.setPayload(data);
    	
    	data.setData(((ICMP) failedIpPacket.getPayload()).getPayload().serialize());
    	
    	super.sendPacket(ether, iface);
    }
    
    private void addPacket(int targetAddress, IPacket packet) {
    	
    	if (packetQueue.containsKey(targetAddress)) {
    		packetQueue.get(targetAddress).add(packet);
    	} else {
    		Queue<IPacket> queue = new LinkedList<IPacket>();
    		queue.add(packet);
    		packetQueue.put(targetAddress, queue);
    		arpRequestCounts.put(targetAddress, 0);
    	}
    }
}
