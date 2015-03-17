package edu.wisc.cs.sdn.vnet.sw;

import java.util.*;
import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{   
    static final long MAPPING_TTL = 15;
    static private class SwitchMapping {
	Iface outIface;
	long  expireTime;
	MACAddress macAddress;
    }
    private Map<MACAddress, SwitchMapping> switchTable;

    /**
     * Creates a router for a specific host.
     * @param host hostname for the router
     */
    public Switch(String host, DumpFile logfile)
    {
	super(host,logfile);
	this.switchTable = new HashMap<MACAddress, SwitchMapping>();
    }

    /**
     * Broadcasts the packet on all available interfaces on this switch.
     */
    private void broadcastPacket(Ethernet etherPacket, Iface inIface)
    {
	Iface interfaces[] = super.getInterfaces().values().toArray(new Iface[0]);
	
	for(Iface outIface : interfaces) {
	    if(!outIface.getName().equals(inIface.getName()))
		super.sendPacket(etherPacket, outIface);
	}
    }


    /**
     * Clean the table to remove all entries that are older than 15S
     */
    private void cleanMappingTable()
    {
	long currTime = System.currentTimeMillis();
	SwitchMapping mappings[] = switchTable.values().toArray(new SwitchMapping[0]);

	for(SwitchMapping mapping : mappings) {
	    if(mapping.expireTime < currTime) {
		switchTable.remove(mapping.macAddress);
	    }
	}
    }

    /**
     * Adds a mapping to the switch table.
     */
    private void addMapping(MACAddress macAddress, Iface outIface)
    {
	SwitchMapping mapping = new SwitchMapping();
	mapping.outIface = outIface;
	mapping.macAddress = macAddress;
	mapping.expireTime = System.currentTimeMillis() + (MAPPING_TTL * 1000);

	this.switchTable.put(macAddress, mapping);
    }

    private void updateMapping(MACAddress macAddress, Iface outIface)
    {
	SwitchMapping mapping = this.switchTable.get(macAddress);

	if(mapping != null && (mapping.outIface.getName().equals(outIface.getName()))) {
	    mapping.expireTime = System.currentTimeMillis() + MAPPING_TTL * 1000;
	    return;
	} else {
	    if(mapping != null) {
		this.switchTable.remove(macAddress);
	    }
	    this.addMapping(macAddress, outIface);
	}
    }

    private SwitchMapping fetchMapping(MACAddress macAddress)
    {
	SwitchMapping mapping = this.switchTable.get(macAddress);

	return mapping;
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
	
	this.cleanMappingTable();
	this.updateMapping(etherPacket.getSourceMAC(), inIface);
	
	SwitchMapping mapping = fetchMapping(etherPacket.getDestinationMAC());
	if(mapping != null) {
	    super.sendPacket(etherPacket, mapping.outIface);
	    System.out.println("-- Send to Iface: " + mapping.outIface.getName() + " -- \n");
	} else {
	    this.broadcastPacket(etherPacket, inIface);
	    System.out.println("-- Broadcast --\n");
	}
    }
}
