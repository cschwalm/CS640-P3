package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.nio.ByteBuffer;

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


    private static short computeChecksum(IPv4 packet) {
	packet.resetChecksum();

	byte[] data = new byte[packet.getHeaderLength() * 4];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.put((byte) (((packet.getVersion() & 0xf) << 4) | (packet.getHeaderLength() & 0xf)));
        bb.put(packet.getDiffServ());
        bb.putShort(packet.getTotalLength());
        bb.putShort(packet.getIdentification());
        bb.putShort((short) (((packet.getFlags() & 0x7) << 13) | (packet.getFragmentOffset() & 0x1fff)));
        bb.put(packet.getTtl());
        bb.put(packet.getProtocol());
        bb.putShort(packet.getChecksum());
        bb.putInt(packet.getSourceAddress());
        bb.putInt(packet.getDestinationAddress());
        if (packet.getOptions() != null)
            bb.put(packet.getOptions());

        // compute checksum if needed
        if (packet.getChecksum() == 0) {
            bb.rewind();
            int accumulation = 0;
            for (int i = 0; i < packet.getHeaderLength() * 2; ++i) {
                accumulation += 0xffff & bb.getShort();
            }
            accumulation = ((accumulation >> 16) & 0xffff)
                    + (accumulation & 0xffff);
            packet.setChecksum((short) (~accumulation & 0xffff));
        }

	return packet.getChecksum();
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
	
	if(etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
	    return;

	IPv4 packet = (IPv4) etherPacket.getPayload();
	short storedChecksum = packet.getChecksum();
	
	if(computeChecksum(packet) != storedChecksum)
	    return;

	Byte ttlByte = packet.getTtl();
	int ttl = ttlByte.intValue() - 1;

	packet.setTtl((byte) ttl);

	if(ttl <= 0) {
		sendICMP(etherPacket, inIface, 11, 0);
	    return;
	}

	Iface interfaces[] = super.interfaces.values().toArray(new Iface[0]);
	for(Iface iface : interfaces) {
	    if(packet.getDestinationAddress() == iface.getIpAddress())
		return;
	}

	RouteEntry routeMapping = this.routeTable.lookup(packet.getDestinationAddress());

	if(routeMapping == null)
	    return;


	ArpEntry arpMapping;
	if(routeMapping.getGatewayAddress() != 0) {
	    arpMapping = this.arpCache.lookup(routeMapping.getGatewayAddress());
	} else {
	    arpMapping = this.arpCache.lookup(packet.getDestinationAddress());
	}

	if(arpMapping == null)
	    return;

	etherPacket.setDestinationMACAddress(arpMapping.getMac().toBytes());
	etherPacket.setSourceMACAddress(routeMapping.getInterface().getMacAddress().toBytes());

	// Recompute the checksum now that we have changed TTL in IP header
	computeChecksum(packet);
	
	if(inIface.getName().equals(routeMapping.getInterface().getName()))
	    return;

	super.sendPacket(etherPacket, routeMapping.getInterface());

	//System.out.println("*** -> Sent packet: " + etherPacket.toString().replace("\n", "\n\t"));
    }
    
    /**
     * Sends an ICMP packet with the specified type and code.
     * 
     * @param type
     * @param code
     */
    private void sendICMP(Ethernet failedEtherPacket, Iface iface, int type, int code) {
    	
    	IPv4 failedIpPacket = (IPv4) failedEtherPacket.getPayload();
    	
    	Ethernet ether = new Ethernet();
    	ether.setEtherType(Ethernet.TYPE_IPv4);
    	
    	
    	/* Flip Source/Dest To Reply Back */
    	ether.setSourceMACAddress(iface.getMacAddress().toBytes());
    	RouteEntry routeMapping = this.routeTable.lookup(failedIpPacket.getSourceAddress());
    	ArpEntry dstAddress = this.arpCache.lookup(routeMapping.getDestinationAddress());
    	ether.setDestinationMACAddress(dstAddress.getMac().toBytes());

    	IPv4 ip = new IPv4();
    	ip.setTtl(new Integer(64).byteValue());
    	ip.setProtocol(IPv4.PROTOCOL_ICMP);
    	ip.setSourceAddress(iface.getIpAddress());
    	ip.setDestinationAddress( ((IPv4) ether.getPayload()).getSourceAddress());
    	
    	ICMP icmp = new ICMP();
    	icmp.setIcmpCode(new Integer(code).byteValue());
    	icmp.setIcmpType(new Integer(type).byteValue());
    	
    	Data data = new Data();
    	ether.setPayload(ip);
    	ip.setPayload(icmp);
    	icmp.setPayload(data);
    	
    	super.sendPacket(ether, iface);
    }
}