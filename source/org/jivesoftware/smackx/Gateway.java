package org.jivesoftware.smackx;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.jivesoftware.smack.Connection;
import org.jivesoftware.smack.PacketCollector;
import org.jivesoftware.smack.PacketListener;
import org.jivesoftware.smack.Roster;
import org.jivesoftware.smack.RosterEntry;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.PacketIDFilter;
import org.jivesoftware.smack.filter.PacketTypeFilter;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.packet.DiscoverInfo;
import org.jivesoftware.smackx.packet.Register;
import org.jivesoftware.smackx.packet.DiscoverInfo.Identity;

public class Gateway {
	
	private Connection connection;
	private ServiceDiscoveryManager sdManager;
	private Roster roster;
	private String entityJID;
	private Register registerInfo;
	private Identity identity;
	private DiscoverInfo info;
	
	Gateway(Connection connection, String entityJID){
		this.connection = connection;
		this.roster = connection.getRoster();
		this.sdManager = ServiceDiscoveryManager.getInstanceFor(connection);
		this.entityJID = entityJID;
	}
	
	Gateway(Connection connection, String entityJID, DiscoverInfo info, Identity identity){
		this(connection, entityJID);
		this.info = info;
		this.identity = identity;
	}
	
	private void discoverInfo() throws XMPPException{
		info = sdManager.discoverInfo(entityJID);
		Iterator<Identity> iterator = info.getIdentities();
		while(iterator.hasNext()){
			Identity temp = iterator.next();
			if(temp.getCategory().equalsIgnoreCase("gateway")){
				this.identity = temp;
				break;
			}
		}
	}
	
	private Identity getIdentity() throws XMPPException{
		if(identity==null){
			discoverInfo();
		}
		return identity;
	}
	
	private Register getRegisterInfo(){
		if(registerInfo==null){
			refreshRegisterInfo();
		}
		return registerInfo;
	}
	
	private void refreshRegisterInfo(){
		Register packet = new Register();
		packet.setFrom(connection.getUser());
		packet.setType(IQ.Type.GET);
		packet.setTo(entityJID);
		PacketCollector collector = 
			connection.createPacketCollector(new PacketIDFilter(packet.getPacketID()));
		connection.sendPacket(packet);
		Packet result = collector.nextResult(SmackConfiguration.getPacketReplyTimeout());
		if(result instanceof Register){ 
			Register register = (Register)result;
			this.registerInfo = register;
		}
	}
	
	public boolean canRegister() throws XMPPException{
		if(info==null){
			discoverInfo();
		}
		return info.containsFeature("jabber:iq:register");
	}
	
	public List<String> getRequiredFields(){
		return getRegisterInfo().getRequiredFields();
	}
	
	public String getName() throws XMPPException{
		if(identity==null){
			discoverInfo();
		}
		return identity.getName();
	}
	
	public String getType() throws XMPPException{
		if(identity==null){
			discoverInfo();
		}
		return identity.getType();
	}
	
	public boolean isRegistered() throws XMPPException{
		return getRegisterInfo().isRegistered();
	}
	
	public String getField(String fieldName){
		return getRegisterInfo().getField(fieldName);
	}
	
	public List<String> getFieldNames(){
		return getRegisterInfo().getFieldNames();
	}
	
	public String getUsername(){
		return getField("username");
	}
	
	public String getPassword(){
		return getField("password");
	}
	
	public String getInstructions(){
		return getRegisterInfo().getInstructions();	
	}
	
	public void register(String username, String password, Map<String,String> fields)throws XMPPException{
		if(getRegisterInfo().isRegistered()) {
			throw new IllegalStateException("You are already registered with this gateway");
		}
		Register register = new Register();
		register.setFrom(connection.getUser());
		register.setTo(entityJID);
		register.setType(IQ.Type.SET);
		register.setUsername(username);
		register.setPassword(password);
		for(String s : fields.keySet()){
			register.addField(s, fields.get(s));
		}
		PacketCollector resultCollector = 
			connection.createPacketCollector(new PacketIDFilter(register.getPacketID())); 
		connection.sendPacket(register);
		Packet result = 
			resultCollector.nextResult(SmackConfiguration.getPacketReplyTimeout());
		if(result!=null && result instanceof IQ){
			IQ resultIQ = (IQ)result;
			if(resultIQ.getError()!=null){
				throw new XMPPException(resultIQ.getError());
			}
			connection.addPacketListener(new GatewayPresenceListener(), 
					new PacketTypeFilter(Presence.class));
			roster.createEntry(entityJID, getIdentity().getName(), new String[]{});
		}
		else{
			throw new XMPPException("Packet reply timeout");
		}
	}
	
	public void register(String username, String password) throws XMPPException{
		register(username, password,new HashMap<String,String>());
	}
	
	public void unregister() throws XMPPException{
		Register register = new Register();
		register.setFrom(connection.getUser());
		register.setTo(entityJID);
		register.setType(IQ.Type.SET);
		register.setRemove(true);
		PacketCollector resultCollector = 
			connection.createPacketCollector(new PacketIDFilter(register.getPacketID()));
		connection.sendPacket(register);
		Packet result = resultCollector.nextResult(SmackConfiguration.getPacketReplyTimeout());
		if(result!=null && result instanceof IQ){
			IQ resultIQ = (IQ)result;
			if(resultIQ.getError()!=null){
				throw new XMPPException(resultIQ.getError());
			}
			RosterEntry gatewayEntry = roster.getEntry(entityJID);
			roster.removeEntry(gatewayEntry);
		}
		else{
			throw new XMPPException("Packet reply timeout");
		}
	}
	
	public void login(){
		Presence presence = new Presence(Presence.Type.available);
		login(presence);
	}
	
	public void login(Presence presence){
		presence.setType(Presence.Type.available);
		presence.setTo(entityJID);
		presence.setFrom(connection.getUser());
		connection.sendPacket(presence);
	}
	
	public void logout(){
		Presence presence = new Presence(Presence.Type.unavailable);
		presence.setTo(entityJID);
		presence.setFrom(connection.getUser());
		connection.sendPacket(presence);
	}
	
	private class GatewayPresenceListener implements PacketListener{

		@Override
		public void processPacket(Packet packet) {
			if(packet instanceof Presence){
				Presence presence = (Presence)packet;
				if(entityJID.equals(presence.getFrom()) && 
						roster.contains(presence.getFrom()) &&
						presence.getType().equals(Presence.Type.subscribe)){
					Presence response = new Presence(Presence.Type.subscribed);
					response.setTo(presence.getFrom());
					response.setFrom(StringUtils.parseBareAddress(connection.getUser()));
					connection.sendPacket(response);
				}
			}
			
		}
	}

}
