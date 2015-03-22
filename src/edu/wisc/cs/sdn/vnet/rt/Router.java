package edu.wisc.cs.sdn.vnet.rt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
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
		// Ignore all other packet types, for now
		}

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
        	{ return; }
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

        // If no entry matched, do nothing
        if (null == bestMatch)
        { return; }

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
        { return; }
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
        	System.out.println("NO MAC ENTRY FOUND!");
        	return;
        }
        
    	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
    	ether.setPayload(ip);
    	
    	ip.setTtl(new Integer(64).byteValue());
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
			byteData.write(failedIpPacket.toString().getBytes());
			byteData.write(failedIpPacket.getPayload().toString().getBytes(), 0, 8);
		} catch (IOException e) {}
    	data.setData(byteData.toByteArray());
    	
    	
    	super.sendPacket(ether, iface);
    }
}
