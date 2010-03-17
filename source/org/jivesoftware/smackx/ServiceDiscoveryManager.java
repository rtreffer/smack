/**
 * $RCSfile$
 * $Revision$
 * $Date$
 *
 * Copyright 2003-2007 Jive Software.
 *
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.smackx;

import org.jivesoftware.smack.*;
import org.jivesoftware.smack.filter.PacketExtensionFilter;
import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.filter.PacketIDFilter;
import org.jivesoftware.smack.filter.PacketTypeFilter;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.PacketExtension;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.provider.PacketExtensionProvider;
import org.jivesoftware.smack.provider.ProviderManager;
import org.jivesoftware.smack.util.Base64;
import org.jivesoftware.smackx.packet.DiscoverInfo;
import org.jivesoftware.smackx.packet.DiscoverItems;
import org.jivesoftware.smackx.packet.DataForm;
import org.jivesoftware.smackx.packet.DiscoverInfo.Identity;
import org.jivesoftware.smackx.packet.DiscoverItems.Item;
import org.xmlpull.v1.XmlPullParser;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages discovery of services in XMPP entities. This class provides:
 * <ol>
 * <li>A registry of supported features in this XMPP entity.
 * <li>Automatic response when this XMPP entity is queried for information.
 * <li>Ability to discover items and information of remote XMPP entities.
 * <li>Ability to publish publicly available items.
 * </ol>  
 * 
 * @author Gaston Dombiak
 */
public class ServiceDiscoveryManager {
	
private class CapsInfoProvider implements NodeInformationProvider{
		
		private String node;
		private List<String> features = new ArrayList<String>();
		private Identity id;
		
		public CapsInfoProvider(String node, List<String> features, Identity id){
			this.node = node;
			this.features = features;
			this.id = id;
		}
		
		public String getNode(){
			return node;
		}

		public List<String> getNodeFeatures() {
			return features;
		}

		public List<Identity> getNodeIdentities() {
			ArrayList<Identity> ids = new ArrayList<Identity>();
			ids.add(id);
			return ids;
		}

		public List<Item> getNodeItems() {
			// TODO Auto-generated method stub
			return null;
		}
	}
	
	public class CapsListener implements PacketListener{

		public void processPacket(Packet packet) {
			CapsVersionExtension ext =
				(CapsVersionExtension)packet.getExtension("c", ServiceDiscoveryManager.CAPS_NS);
			if(ext!=null && ext.getNode()!=null && ext.getVersion()!=null){
				String ver = ext.getNode()+"#"+ext.getVersion();
				String user = packet.getFrom();
				addUserCapsNode(user,ver);
			}
		}
	}
	
	public static class CapsVersionProvider implements PacketExtensionProvider{

		public PacketExtension parseExtension(XmlPullParser parser)
				throws Exception {
			boolean done=false;
			String hash=null;
			String version=null;
			String node=null;
			while(!done){
				
				if(parser.getEventType()==XmlPullParser.START_TAG &&
						parser.getName().equalsIgnoreCase("c")){
					hash = parser.getAttributeValue(null, "hash");
					version = parser.getAttributeValue(null, "ver");
					node = parser.getAttributeValue(null, "node");
				}
				
				if(parser.getEventType()==XmlPullParser.END_TAG &&
						parser.getName().equalsIgnoreCase("c")){
					done=true;
				}
				else{
					parser.next();
				}
			}
			
			//if(hash !=null && version != null && node != null){
			//It seems that we have to always return an extension object and shouldn't
			//return null or throw an exception
			return new CapsVersionExtension(node,version,hash);
			//}
			//Log.w("DiscoManager","Wasn't a Caps Extension");
			//return null;
		}
		
	}
	
	public static class CapsVersionExtension implements PacketExtension{
		
		public static final String elementName="c";
		public static final String NS=ServiceDiscoveryManager.CAPS_NS;
		
		private String hash="sha-1";
		private String node;
		private String version;
		
		public CapsVersionExtension(String node, String version){
			this.node = node;
			this.version = version;
		}
		
		public CapsVersionExtension(String node, String version, String hash){
			this(node,version);
			this.hash = hash;
		}

		public String getElementName() {
			return elementName;
		}

		public String getNamespace() {
			return NS;
		}

		public String toXML() {
			String out="<c xmlns=\""+NS+"\" "+
				"hash=\""+hash+"\" "+
				"node=\""+node+"\" "+
				"ver=\""+version+"\"/>";
			return out;
		}
		
		public String getNode(){
			return node;
		}
		
		public String getVersion(){
			return version;
		}
	}
	
	private class CapsInterceptor implements PacketInterceptor{

		public void interceptPacket(Packet arg0) {
			arg0.addExtension(new CapsVersionExtension(entityNode,currentCapsVersion));
			presenceSend = true;
		}
	}

    private static String identityName = "Smack";
    private static String identityType = "pc";
    private static String entityNode = "http://www.igniterealtime.org/projects/smack/";
    
    public static final String HASH_METHOD = "sha-1";
    public static final String HASH_METHOD_CAPS = "SHA-1";
    public static final String CAPS_NS="http://jabber.org/protocol/caps";
    
    private static Map<String,DiscoverInfo> caps =
        new ConcurrentHashMap<String,DiscoverInfo>();
    
    private Map<String,String> userCaps =
        new ConcurrentHashMap<String,String>();
    
    private Map<String,DiscoverInfo> nonCapsInfos =
    	new ConcurrentHashMap<String,DiscoverInfo>();
    
    private String currentCapsVersion = null;
    
    private boolean presenceSend=false;
    
    private CapsListener capsListener = new CapsListener();
	private CapsInterceptor capsInterceptor = new CapsInterceptor();
	//private QueryResponder queryResponder = new QueryResponder();
	private PacketFilter interceptorFilter = new PacketTypeFilter(Presence.class);
	private PacketFilter queryFilter = new PacketTypeFilter(DiscoverInfo.class);
	private PacketFilter listenerFilter = new PacketExtensionFilter("c", CAPS_NS);

    private static Map<Connection, ServiceDiscoveryManager> instances =
            new ConcurrentHashMap<Connection, ServiceDiscoveryManager>();

    private Connection connection;
    private final List<String> features = new ArrayList<String>();
    private DataForm extendedInfo = null;
    private Map<String, NodeInformationProvider> nodeInformationProviders =
            new ConcurrentHashMap<String, NodeInformationProvider>();

    // Create a new ServiceDiscoveryManager on every established connection
    static {
        Connection.addConnectionCreationListener(new ConnectionCreationListener() {
            public void connectionCreated(Connection connection) {
                new ServiceDiscoveryManager(connection);
            }
        });
    }
    
    static{
		ProviderManager.getInstance().addExtensionProvider("c", ServiceDiscoveryManager.CAPS_NS, 
				new CapsVersionProvider());
	}

    /**
     * Creates a new ServiceDiscoveryManager for a given Connection. This means that the 
     * service manager will respond to any service discovery request that the connection may
     * receive. 
     * 
     * @param connection the connection to which a ServiceDiscoveryManager is going to be created.
     */
    public ServiceDiscoveryManager(Connection connection) {
        this.connection = connection;
        init();
    }

    /**
     * Returns the ServiceDiscoveryManager instance associated with a given Connection.
     * 
     * @param connection the connection used to look for the proper ServiceDiscoveryManager.
     * @return the ServiceDiscoveryManager associated with a given Connection.
     */
    public static ServiceDiscoveryManager getInstanceFor(Connection connection) {
        return instances.get(connection);
    }

    /**
     * Returns the name of the client that will be returned when asked for the client identity
     * in a disco request. The name could be any value you need to identity this client.
     * 
     * @return the name of the client that will be returned when asked for the client identity
     *          in a disco request.
     */
    public static String getIdentityName() {
        return identityName;
    }

    /**
     * Sets the name of the client that will be returned when asked for the client identity
     * in a disco request. The name could be any value you need to identity this client.
     * 
     * @param name the name of the client that will be returned when asked for the client identity
     *          in a disco request.
     */
    public static void setIdentityName(String name) {
        identityName = name;
    }

    /**
     * Returns the type of client that will be returned when asked for the client identity in a 
     * disco request. The valid types are defined by the category client. Follow this link to learn 
     * the possible types: <a href="http://www.jabber.org/registrar/disco-categories.html#client">Jabber::Registrar</a>.
     * 
     * @return the type of client that will be returned when asked for the client identity in a 
     *          disco request.
     */
    public static String getIdentityType() {
        return identityType;
    }

    /**
     * Sets the type of client that will be returned when asked for the client identity in a 
     * disco request. The valid types are defined by the category client. Follow this link to learn 
     * the possible types: <a href="http://www.jabber.org/registrar/disco-categories.html#client">Jabber::Registrar</a>.
     * 
     * @param type the type of client that will be returned when asked for the client identity in a 
     *          disco request.
     */
    public static void setIdentityType(String type) {
        identityType = type;
    }

    /**
     * Initializes the packet listeners of the connection that will answer to any
     * service discovery request. 
     */
    private void init() {
        // Register the new instance and associate it with the connection 
        instances.put(connection, this);
        // Add a listener to the connection that removes the registered instance when
        // the connection is closed
        connection.addConnectionListener(new ConnectionListener() {
            public void connectionClosed() {
                // Unregister this instance since the connection has been closed
                instances.remove(connection);
            }

            public void connectionClosedOnError(Exception e) {
                // ignore
            }

            public void reconnectionFailed(Exception e) {
                // ignore
            }

            public void reconnectingIn(int seconds) {
                // ignore
            }

            public void reconnectionSuccessful() {
                // ignore
            }
        });

        // Listen for disco#items requests and answer with an empty result        
        PacketFilter packetFilter = new PacketTypeFilter(DiscoverItems.class);
        PacketListener packetListener = new PacketListener() {
            public void processPacket(Packet packet) {
                DiscoverItems discoverItems = (DiscoverItems) packet;
                // Send back the items defined in the client if the request is of type GET
                if (discoverItems != null && discoverItems.getType() == IQ.Type.GET) {
                    DiscoverItems response = new DiscoverItems();
                    response.setType(IQ.Type.RESULT);
                    response.setTo(discoverItems.getFrom());
                    response.setPacketID(discoverItems.getPacketID());
                    response.setNode(discoverItems.getNode());

                    // Add the defined items related to the requested node. Look for 
                    // the NodeInformationProvider associated with the requested node.  
                    NodeInformationProvider nodeInformationProvider =
                            getNodeInformationProvider(discoverItems.getNode());
                    if (nodeInformationProvider != null) {
                        // Specified node was found
                        List<DiscoverItems.Item> items = nodeInformationProvider.getNodeItems();
                        if (items != null) {
                            for (DiscoverItems.Item item : items) {
                                response.addItem(item);
                            }
                        }
                    } else if(discoverItems.getNode() != null) {
                        // Return <item-not-found/> error since client doesn't contain
                        // the specified node
                        response.setType(IQ.Type.ERROR);
                        response.setError(new XMPPError(XMPPError.Condition.item_not_found));
                    }
                    connection.sendPacket(response);
                }
            }
        };
        connection.addPacketListener(packetListener, packetFilter);

        // Listen for disco#info requests and answer the client's supported features 
        // To add a new feature as supported use the #addFeature message        
        packetFilter = new PacketTypeFilter(DiscoverInfo.class);
        packetListener = new PacketListener() {
            public void processPacket(Packet packet) {
                DiscoverInfo discoverInfo = (DiscoverInfo) packet;
                // Answer the client's supported features if the request is of the GET type
                if (discoverInfo != null && discoverInfo.getType() == IQ.Type.GET) {
                    DiscoverInfo response = new DiscoverInfo();
                    response.setType(IQ.Type.RESULT);
                    response.setTo(discoverInfo.getFrom());
                    response.setPacketID(discoverInfo.getPacketID());
                    response.setNode(discoverInfo.getNode());
                     // Add the client's identity and features only if "node" is null
                    if (discoverInfo.getNode() == null) {
                        // Set this client identity
                        DiscoverInfo.Identity identity = new DiscoverInfo.Identity("client",
                                getIdentityName());
                        identity.setType(getIdentityType());
                        response.addIdentity(identity);
                        // Add the registered features to the response
                        synchronized (features) {
                            for (Iterator<String> it = getFeatures(); it.hasNext();) {
                                response.addFeature(it.next());
                            }
                            if (extendedInfo != null) {
                                response.addExtension(extendedInfo);
                            }
                        }
                    }
                    else {
                        // Disco#info was sent to a node. Check if we have information of the
                        // specified node
                        NodeInformationProvider nodeInformationProvider =
                                getNodeInformationProvider(discoverInfo.getNode());
                        if (nodeInformationProvider != null) {
                            // Node was found. Add node features
                            List<String> features = nodeInformationProvider.getNodeFeatures();
                            if (features != null) {
                                for(String feature : features) {
                                    response.addFeature(feature);
                                }
                            }
                            // Add node identities
                            List<DiscoverInfo.Identity> identities =
                                    nodeInformationProvider.getNodeIdentities();
                            if (identities != null) {
                                for (DiscoverInfo.Identity identity : identities) {
                                    response.addIdentity(identity);
                                }
                            }
                        }
                        else {
                            // Return <item-not-found/> error since specified node was not found
                            response.setType(IQ.Type.ERROR);
                            response.setError(new XMPPError(XMPPError.Condition.item_not_found));
                        }
                    }
                    connection.sendPacket(response);
                }
            }
        };
        connection.addPacketListener(packetListener, packetFilter);
        addFeature("http://jabber.org/protocol/caps");
        connection.addPacketListener(capsListener, listenerFilter);
        connection.addPacketInterceptor(capsInterceptor, interceptorFilter);
        //connection.addPacketInterceptor(queryResponder, queryFilter);
    }

    /**
     * Returns the NodeInformationProvider responsible for providing information 
     * (ie items) related to a given node or <tt>null</null> if none.<p>
     * 
     * In MUC, a node could be 'http://jabber.org/protocol/muc#rooms' which means that the
     * NodeInformationProvider will provide information about the rooms where the user has joined.
     * 
     * @param node the node that contains items associated with an entity not addressable as a JID.
     * @return the NodeInformationProvider responsible for providing information related 
     * to a given node.
     */
    private NodeInformationProvider getNodeInformationProvider(String node) {
        if (node == null) {
            return null;
        }
        return nodeInformationProviders.get(node);
    }

    /**
     * Sets the NodeInformationProvider responsible for providing information 
     * (ie items) related to a given node. Every time this client receives a disco request
     * regarding the items of a given node, the provider associated to that node will be the 
     * responsible for providing the requested information.<p>
     * 
     * In MUC, a node could be 'http://jabber.org/protocol/muc#rooms' which means that the
     * NodeInformationProvider will provide information about the rooms where the user has joined. 
     * 
     * @param node the node whose items will be provided by the NodeInformationProvider.
     * @param listener the NodeInformationProvider responsible for providing items related
     *      to the node.
     */
    public void setNodeInformationProvider(String node, NodeInformationProvider listener) {
        nodeInformationProviders.put(node, listener);
    }

    /**
     * Removes the NodeInformationProvider responsible for providing information 
     * (ie items) related to a given node. This means that no more information will be
     * available for the specified node.
     * 
     * In MUC, a node could be 'http://jabber.org/protocol/muc#rooms' which means that the
     * NodeInformationProvider will provide information about the rooms where the user has joined. 
     * 
     * @param node the node to remove the associated NodeInformationProvider.
     */
    public void removeNodeInformationProvider(String node) {
        nodeInformationProviders.remove(node);
    }

    /**
     * Returns the supported features by this XMPP entity.
     * 
     * @return an Iterator on the supported features by this XMPP entity.
     */
    public Iterator<String> getFeatures() {
        synchronized (features) {
            return Collections.unmodifiableList(new ArrayList<String>(features)).iterator();
        }
    }

    /**
     * Registers that a new feature is supported by this XMPP entity. When this client is 
     * queried for its information the registered features will be answered.<p>
     *
     * Since no packet is actually sent to the server it is safe to perform this operation
     * before logging to the server. In fact, you may want to configure the supported features
     * before logging to the server so that the information is already available if it is required
     * upon login.
     *
     * @param feature the feature to register as supported.
     */
    public void addFeature(String feature) {
        synchronized (features) {
            features.add(feature);
            ownVerChanged();
        }
    }

    /**
     * Removes the specified feature from the supported features by this XMPP entity.<p>
     *
     * Since no packet is actually sent to the server it is safe to perform this operation
     * before logging to the server.
     *
     * @param feature the feature to remove from the supported features.
     */
    public void removeFeature(String feature) {
        synchronized (features) {
            features.remove(feature);
        }
    }

    /**
     * Returns true if the specified feature is registered in the ServiceDiscoveryManager.
     *
     * @param feature the feature to look for.
     * @return a boolean indicating if the specified featured is registered or not.
     */
    public boolean includesFeature(String feature) {
        synchronized (features) {
            return features.contains(feature);
        }
    }

    /**
     * Registers extended discovery information of this XMPP entity. When this
     * client is queried for its information this data form will be returned as
     * specified by XEP-0128.
     * <p>
     *
     * Since no packet is actually sent to the server it is safe to perform this
     * operation before logging to the server. In fact, you may want to
     * configure the extended info before logging to the server so that the
     * information is already available if it is required upon login.
     *
     * @param info
     *            the data form that contains the extend service discovery
     *            information.
     */
    public void setExtendedInfo(DataForm info) {
      extendedInfo = info;
    }

    /**
     * Removes the dataform containing extended service discovery information
     * from the information returned by this XMPP entity.<p>
     *
     * Since no packet is actually sent to the server it is safe to perform this
     * operation before logging to the server.
     */
    public void removeExtendedInfo() {
       extendedInfo = null;
    }

    /**
     * Returns the discovered information of a given XMPP entity addressed by its JID.
     * 
     * @param entityID the address of the XMPP entity.
     * @return the discovered information.
     * @throws XMPPException if the operation failed for some reason.
     */
    public DiscoverInfo discoverInfo(String entityID) throws XMPPException {
       // return discoverInfo(entityID, null);
    	DiscoverInfo info = null;
		if(userCaps.containsKey(entityID)){
			String capsVersion = userCaps.get(entityID);
			if(caps.containsKey(capsVersion)){
				return caps.get(capsVersion);
			}
			else{
				info = discoverInfo(entityID, capsVersion);
				caps.put(capsVersion, info);
			}
		}
		else{
			if(nonCapsInfos.containsKey(entityID)){
				info = nonCapsInfos.get(entityID);
			}
			else{
				info = discoverInfo(entityID);
				nonCapsInfos.put(entityID, info);
			}
		}
		return info;
    }

    /**
     * Returns the discovered information of a given XMPP entity addressed by its JID and
     * note attribute. Use this message only when trying to query information which is not 
     * directly addressable.
     * 
     * @param entityID the address of the XMPP entity.
     * @param node the attribute that supplements the 'jid' attribute.
     * @return the discovered information.
     * @throws XMPPException if the operation failed for some reason.
     */
    public DiscoverInfo discoverInfo(String entityID, String node) throws XMPPException {
        // Discover the entity's info
        DiscoverInfo disco = new DiscoverInfo();
        disco.setType(IQ.Type.GET);
        disco.setTo(entityID);
        disco.setNode(node);

        // Create a packet collector to listen for a response.
        PacketCollector collector =
            connection.createPacketCollector(new PacketIDFilter(disco.getPacketID()));

        connection.sendPacket(disco);

        // Wait up to 5 seconds for a result.
        IQ result = (IQ) collector.nextResult(SmackConfiguration.getPacketReplyTimeout());
        // Stop queuing results
        collector.cancel();
        if (result == null) {
            throw new XMPPException("No response from the server.");
        }
        if (result.getType() == IQ.Type.ERROR) {
            throw new XMPPException(result.getError());
        }
        return (DiscoverInfo) result;
    }

    /**
     * Returns the discovered items of a given XMPP entity addressed by its JID.
     * 
     * @param entityID the address of the XMPP entity.
     * @return the discovered information.
     * @throws XMPPException if the operation failed for some reason.
     */
    public DiscoverItems discoverItems(String entityID) throws XMPPException {
        return discoverItems(entityID, null);
    }

    /**
     * Returns the discovered items of a given XMPP entity addressed by its JID and
     * note attribute. Use this message only when trying to query information which is not 
     * directly addressable.
     * 
     * @param entityID the address of the XMPP entity.
     * @param node the attribute that supplements the 'jid' attribute.
     * @return the discovered items.
     * @throws XMPPException if the operation failed for some reason.
     */
    public DiscoverItems discoverItems(String entityID, String node) throws XMPPException {
        // Discover the entity's items
        DiscoverItems disco = new DiscoverItems();
        disco.setType(IQ.Type.GET);
        disco.setTo(entityID);
        disco.setNode(node);

        // Create a packet collector to listen for a response.
        PacketCollector collector =
            connection.createPacketCollector(new PacketIDFilter(disco.getPacketID()));

        connection.sendPacket(disco);

        // Wait up to 5 seconds for a result.
        IQ result = (IQ) collector.nextResult(SmackConfiguration.getPacketReplyTimeout());
        // Stop queuing results
        collector.cancel();
        if (result == null) {
            throw new XMPPException("No response from the server.");
        }
        if (result.getType() == IQ.Type.ERROR) {
            throw new XMPPException(result.getError());
        }
        return (DiscoverItems) result;
    }

    /**
     * Returns true if the server supports publishing of items. A client may wish to publish items
     * to the server so that the server can provide items associated to the client. These items will
     * be returned by the server whenever the server receives a disco request targeted to the bare
     * address of the client (i.e. user@host.com).
     * 
     * @param entityID the address of the XMPP entity.
     * @return true if the server supports publishing of items.
     * @throws XMPPException if the operation failed for some reason.
     */
    public boolean canPublishItems(String entityID) throws XMPPException {
        DiscoverInfo info = discoverInfo(entityID);
        return info.containsFeature("http://jabber.org/protocol/disco#publish");
    }

    /**
     * Publishes new items to a parent entity. The item elements to publish MUST have at least 
     * a 'jid' attribute specifying the Entity ID of the item, and an action attribute which 
     * specifies the action being taken for that item. Possible action values are: "update" and 
     * "remove".
     * 
     * @param entityID the address of the XMPP entity.
     * @param discoverItems the DiscoveryItems to publish.
     * @throws XMPPException if the operation failed for some reason.
     */
    public void publishItems(String entityID, DiscoverItems discoverItems)
            throws XMPPException {
        publishItems(entityID, null, discoverItems);
    }

    /**
     * Publishes new items to a parent entity and node. The item elements to publish MUST have at 
     * least a 'jid' attribute specifying the Entity ID of the item, and an action attribute which 
     * specifies the action being taken for that item. Possible action values are: "update" and 
     * "remove".
     * 
     * @param entityID the address of the XMPP entity.
     * @param node the attribute that supplements the 'jid' attribute.
     * @param discoverItems the DiscoveryItems to publish.
     * @throws XMPPException if the operation failed for some reason.
     */
    public void publishItems(String entityID, String node, DiscoverItems discoverItems)
            throws XMPPException {
        discoverItems.setType(IQ.Type.SET);
        discoverItems.setTo(entityID);
        discoverItems.setNode(node);

        // Create a packet collector to listen for a response.
        PacketCollector collector =
            connection.createPacketCollector(new PacketIDFilter(discoverItems.getPacketID()));

        connection.sendPacket(discoverItems);

        // Wait up to 5 seconds for a result.
        IQ result = (IQ) collector.nextResult(SmackConfiguration.getPacketReplyTimeout());
        // Stop queuing results
        collector.cancel();
        if (result == null) {
            throw new XMPPException("No response from the server.");
        }
        if (result.getType() == IQ.Type.ERROR) {
            throw new XMPPException(result.getError());
        }
    }
    
	public void addUserCapsNode(String user, String node) {
		userCaps.put(user, node);
	}
	
	public void removeUserCapsNode(String user) {
        userCaps.remove(user);
    }
	
	public String getNodeVersionByUser(String user) {
        return userCaps.get(user);
    }
	
	public String getCapsVersion() {
        return currentCapsVersion;
    }
	
	public void setNode(String node) {
        entityNode = node;
    }
	
	public static DiscoverInfo getDiscoverInfoByNode(String node) {
        return caps.get(node);
    }
	
	private static void cleanupDicsoverInfo(DiscoverInfo info) {
        info.setFrom(null);
        info.setTo(null);
        info.setPacketID(null);
    }
	
	public static void addDiscoverInfoByNode(String node, DiscoverInfo info) {
        cleanupDicsoverInfo(info);

        caps.put(node, info);
    }
	
	public void setCurrentCapsVersion(DiscoverInfo discoverInfo, String capsVersion) {
        currentCapsVersion = capsVersion;
        addDiscoverInfoByNode(getNode() + "#" + capsVersion, discoverInfo);
    }
	
	void calculateEntityCapsVersion(DiscoverInfo discoverInfo,
            String identityType,
            String identityName, List<String> features,
            DataForm extendedInfo) {
        String s = "";

        // Add identity
        // FIXME language
        s += "client/" + identityType + "//" + identityName + "<";

        // Add features
        synchronized (features) {
            SortedSet<String> fs = new TreeSet<String>();
            for (String f : features) {
                fs.add(f);
            }

            for (String f : fs) {
                s += f + "<";
            }
        }

        if (extendedInfo != null) {
            synchronized (extendedInfo) {
                SortedSet<FormField> fs = new TreeSet<FormField>(
                        new Comparator<FormField>() {
                            public int compare(FormField f1, FormField f2) {
                                return f1.getVariable().compareTo(f2.getVariable());
                            }
                        });

                FormField ft = null;

                for (Iterator<FormField> i = extendedInfo.getFields(); i.hasNext();) {
                    FormField f = i.next();
                    if (!f.getVariable().equals("FORM_TYPE")) {
                        fs.add(f);
                    }
                    else {
                        ft = f;
                    }
                }

                // Add FORM_TYPE values
                if (ft != null) {
                    s += formFieldValuesToCaps(ft.getValues());
                }

                // Add the other values
                for (FormField f : fs) {
                    s += f.getVariable() + "<";
                    s += formFieldValuesToCaps(f.getValues());
                }
            }
        }
        setCurrentCapsVersion(discoverInfo, capsToHash(s));
    }
	
	private static String formFieldValuesToCaps(Iterator<String> i) {
        String s = "";
        SortedSet<String> fvs = new TreeSet<String>();
        for (; i.hasNext();) {
            fvs.add(i.next());
        }
        for (String fv : fvs) {
            s += fv + "<";
        }
        return s;
    }
	
	public String getNode(){
		return entityNode;
	}
	
	private static String capsToHash(String capsString) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_METHOD_CAPS);
            byte[] digest = md.digest(capsString.getBytes());
            return Base64.encodeBytes(digest);
        }
        catch (NoSuchAlgorithmException nsae) {
            return null;
        }
    }
	
	public void addDiscoverInfoTo(DiscoverInfo response) {
        // Set this client identity
        DiscoverInfo.Identity identity = new DiscoverInfo.Identity("client",
                getIdentityName());
        identity.setType(getIdentityType());
        response.addIdentity(identity);
        // Add the registered features to the response
        // Add Entity Capabilities (XEP-0115) feature node.
        response.addFeature("http://jabber.org/protocol/caps");
        for (Iterator<String> it = getFeatures(); it.hasNext();) {
            response.addFeature(it.next());
        }
        if (extendedInfo != null) {
            response.addExtension(extendedInfo);
        }
    }
	
	private void ownVerChanged(){
		//notify of version changes
		ArrayList<String> features = new ArrayList<String>();
		Iterator<String> i = getFeatures();
		while(i.hasNext()){
			features.add(i.next());
		}
		calculateEntityCapsVersion(getOwnDiscoverInfo(),getIdentityType(),
				getIdentityName(),features,extendedInfo);
		Identity id = new Identity("client",getIdentityName());
		id.setType(getIdentityType());
		CapsInfoProvider infos = new CapsInfoProvider(getNode()+"#"+currentCapsVersion,
				features,id);
		if(presenceSend){
			Presence presence = new Presence(Presence.Type.available);
			connection.sendPacket(presence);
		}
		setNodeInformationProvider(infos.getNode(), infos);
	}
	
	public DiscoverInfo getOwnDiscoverInfo() {
        DiscoverInfo di = new DiscoverInfo();
        di.setType(IQ.Type.RESULT);
        di.setNode(getNode() + "#" + currentCapsVersion);

        // Add discover info
        addDiscoverInfoTo(di);

        return di;
    }
}