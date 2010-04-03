package org.jivesoftware.smackx;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.jivesoftware.smack.Connection;
import org.jivesoftware.smack.Roster;
import org.jivesoftware.smack.RosterEntry;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.packet.DiscoverInfo;
import org.jivesoftware.smackx.packet.DiscoverItems;
import org.jivesoftware.smackx.packet.DiscoverInfo.Identity;
import org.jivesoftware.smackx.packet.DiscoverItems.Item;

public class GatewayManager {
	
	private static Map<Connection,GatewayManager> instances = 
		new HashMap<Connection,GatewayManager>();
	
	private ServiceDiscoveryManager sdManager;
	
	private Map<String,Gateway> localGateways = new HashMap<String,Gateway>();
	
	private Map<String,Gateway> nonLocalGateways = new HashMap<String,Gateway>();
	
	private Map<String,Gateway> gateways = new HashMap<String,Gateway>();
	
	private Connection connection;
	
	private Roster roster;
	
	private GatewayManager(){
		
	}
	
	private GatewayManager(Connection connection) throws XMPPException{
		this.connection = connection;
		this.roster = connection.getRoster();
		sdManager = ServiceDiscoveryManager.getInstanceFor(connection);
	}
	
	private void loadLocalGateways() throws XMPPException{
		DiscoverItems items = sdManager.discoverItems(connection.getHost());
		Iterator<Item> iter = items.getItems();
		while(iter.hasNext()){
			String itemJID = iter.next().getEntityID();
			discoverGateway(itemJID);
		}
	}
	
	private void discoverGateway(String itemJID) throws XMPPException{
		DiscoverInfo info = sdManager.discoverInfo(itemJID);
		Iterator<Identity> i = info.getIdentities();
		
		while(i.hasNext()){
			Identity identity = i.next();
			String category = identity.getCategory();
			if(category.toLowerCase().equals("gateway")){
				gateways.put(itemJID, new Gateway(connection,itemJID));
				if(itemJID.contains(connection.getHost())){
					localGateways.put(itemJID, 
							new Gateway(connection,itemJID,info,identity));
				}
				else{
					nonLocalGateways.put(itemJID, 
							new Gateway(connection,itemJID,info,identity));
				}
				break;
			}
		}
	}
	
	private void loadNonLocalGateways() throws XMPPException{
		if(roster!=null){
			for(RosterEntry entry : roster.getEntries()){
				if(entry.getUser().equalsIgnoreCase(StringUtils.parseServer(entry.getUser())) &&
						!entry.getUser().contains(connection.getHost())){
					discoverGateway(entry.getUser());
				}
			}
		}
	}
	
	public GatewayManager getInstanceFor(Connection connection) throws XMPPException{
		synchronized(instances){
			if(instances.containsKey(connection)){
				return instances.get(connection);
			}
			GatewayManager instance = new GatewayManager(connection);
			instances.put(connection, instance);
			return instance;
		}
	}
	
	public List<Gateway> getLocalGateways() throws XMPPException{
		if(localGateways.size()==0){
			loadLocalGateways();
		}
		return new ArrayList<Gateway>(localGateways.values());
	}
	
	public List<Gateway> getNonLocalGateways() throws XMPPException{
		if(nonLocalGateways.size()==0){
			loadNonLocalGateways();
		}
		return new ArrayList<Gateway>(nonLocalGateways.values());
	}
	
	public void refreshNonLocalGateways() throws XMPPException{
		loadNonLocalGateways();
	}
	
	public Gateway getGateway(String entityJID){
		if(localGateways.containsKey(entityJID)){
			return localGateways.get(entityJID);
		}
		if(nonLocalGateways.containsKey(entityJID)){
			return nonLocalGateways.get(entityJID);
		}
		
		Gateway gateway = new Gateway(connection,entityJID);
		if(entityJID.contains(connection.getHost())){
			localGateways.put(entityJID, gateway);
		}
		else{
			nonLocalGateways.put(entityJID, gateway);
		}
		gateways.put(entityJID, gateway);
		return gateway;
	}

}
