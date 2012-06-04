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

package org.jivesoftware.smack;

import org.jivesoftware.smack.Connection.ListenerWrapper;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.sasl.SASLMechanism.Challenge;
import org.jivesoftware.smack.sasl.SASLMechanism.Failure;
import org.jivesoftware.smack.sasl.SASLMechanism.Success;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smackx.ServiceDiscoveryManager;
import org.xmlpull.mxp1.MXParser;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.util.concurrent.*;

/**
 * Listens for XML traffic from the XMPP server and parses it into packet objects.
 * The packet reader also invokes all packet listeners and collectors.<p>
 *
 * @see Connection#createPacketCollector
 * @see Connection#addPacketListener
 * @author Matt Tucker
 */
class PacketReader {

    private Thread readerThread;
    private ExecutorService listenerExecutor;

    private XMPPConnection connection;
    private XmlPullParser parser;
    private boolean done;

    private String connectionID = null;

    protected PacketReader(final XMPPConnection connection) {
        this.connection = connection;
        this.init();
    }

    /**
     * Initializes the reader in order to be used. The reader is initialized during the
     * first connection and when reconnecting due to an abruptly disconnection.
     */
    protected void init() {
        done = false;
        connectionID = null;

        readerThread = new Thread() {
            public void run() {
                parsePackets(this);
            }
        };
        readerThread.setName("Smack Packet Reader (" + connection.connectionCounterValue + ")");
        readerThread.setDaemon(true);

        // Create an executor to deliver incoming packets to listeners. We'll use a single
        // thread with an unbounded queue.
        listenerExecutor = Executors.newSingleThreadExecutor(new ThreadFactory() {

            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable,
                        "Smack Listener Processor (" + connection.connectionCounterValue + ")");
                thread.setDaemon(true);
                return thread;
            }
        });

        resetParser();
    }

    /**
     * Starts the packet reader thread and returns once a connection to the server
     * has been established. A connection will be attempted for a maximum of five
     * seconds. An XMPPException will be thrown if the connection fails.
     *
     * @throws XMPPException if the server fails to send an opening stream back
     *      for more than five seconds.
     */
    synchronized public void startup() throws XMPPException {
        readerThread.start();
        // Wait for stream tag before returing. We'll wait a couple of seconds before
        // giving up and throwing an error.
        try {
            // A waiting thread may be woken up before the wait time or a notify
            // (although this is a rare thing). Therefore, we continue waiting
            // until either a connectionID has been set (and hence a notify was
            // made) or the total wait time has elapsed.
            int waitTime = SmackConfiguration.getPacketReplyTimeout();
            wait(3 * waitTime);
        }
        catch (InterruptedException ie) {
            // Ignore.
        }
        if (connectionID == null) {
            throw new XMPPException("Connection failed. No response from server.");
        }
        else {
            connection.connectionID = connectionID;
        }
    }

    /**
     * Shuts the packet reader down.
     */
    public void shutdown() {
        // Notify connection listeners of the connection closing if done hasn't already been set.
        if (!done) {
            for (ConnectionListener listener : connection.getConnectionListeners()) {
                try {
                    listener.connectionClosed();
                }
                catch (Exception e) {
                    // Cath and print any exception so we can recover
                    // from a faulty listener and finish the shutdown process
                    e.printStackTrace();
                }
            }
        }
        done = true;

        // Shut down the listener executor.
        listenerExecutor.shutdown();
    }

    /**
     * Cleans up all resources used by the packet reader.
     */
    void cleanup() {
        connection.recvListeners.clear();
        connection.collectors.clear();
    }

    /**
     * Sends out a notification that there was an error with the connection
     * and closes the connection.
     *
     * @param e the exception that causes the connection close event.
     */
    void notifyConnectionError(Exception e) {
        done = true;
        // Closes the connection temporary. A reconnection is possible
        connection.shutdown(new Presence(Presence.Type.unavailable));
        // Print the stack trace to help catch the problem
        e.printStackTrace();
        // Notify connection listeners of the error.
        for (ConnectionListener listener : connection.getConnectionListeners()) {
            try {
                listener.connectionClosedOnError(e);
            }
            catch (Exception e2) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                e2.printStackTrace();
            }
        }
    }

    /**
     * Sends a notification indicating that the connection was reconnected successfully.
     */
    protected void notifyReconnection() {
        // Notify connection listeners of the reconnection.
        for (ConnectionListener listener : connection.getConnectionListeners()) {
            try {
                listener.reconnectionSuccessful();
            }
            catch (Exception e) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                e.printStackTrace();
            }
        }
    }

    /**
     * Resets the parser using the latest connection's reader. Reseting the parser is necessary
     * when the plain connection has been secured or when a new opening stream element is going
     * to be sent by the server.
     */
    private void resetParser() {
        try {
            parser = new MXParser();
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
            parser.setInput(connection.reader);
        }
        catch (XmlPullParserException xppe) {
            xppe.printStackTrace();
        }
    }

    /**
     * Parse top-level packets in order to process them further.
     *
     * @param thread the thread that is being used by the reader to parse incoming packets.
     */
    private void parsePackets(Thread thread) {
        try {
            int eventType = parser.getEventType();
            do {
                if (eventType == XmlPullParser.START_TAG) {
                    if (parser.getName().equals("message")) {
                        processPacket(PacketParserUtils.parseMessage(parser));
                    }
                    else if (parser.getName().equals("iq")) {
                        processPacket(PacketParserUtils.parseIQ(parser, connection));
                    }
                    else if (parser.getName().equals("presence")) {
                        processPacket(PacketParserUtils.parsePresence(parser));
                    }
                    // We found an opening stream. Record information about it, then notify
                    // the connectionID lock so that the packet reader startup can finish.
                    else if (parser.getName().equals("stream")) {
                        // Ensure the correct jabber:client namespace is being used.
                        if ("jabber:client".equals(parser.getNamespace(null))) {
                            // Get the connection id.
                            for (int i=0; i<parser.getAttributeCount(); i++) {
                                if (parser.getAttributeName(i).equals("id")) {
                                    // Save the connectionID
                                    connectionID = parser.getAttributeValue(i);
                                    if (!"1.0".equals(parser.getAttributeValue("", "version"))) {
                                        // Notify that a stream has been opened if the
                                        // server is not XMPP 1.0 compliant otherwise make the
                                        // notification after TLS has been negotiated or if TLS
                                        // is not supported
                                        releaseConnectionIDLock();
                                    }
                                }
                                else if (parser.getAttributeName(i).equals("from")) {
                                    // Use the server name that the server says that it is.
                                    connection.config.setServiceName(parser.getAttributeValue(i));
                                }
                            }
                        }
                    }
                    else if (parser.getName().equals("error")) {
                        throw new XMPPException(PacketParserUtils.parseStreamError(parser));
                    }
                    else if (parser.getName().equals("features")) {
                        parseFeatures(parser);
                    }
                    else if (parser.getName().equals("proceed")) {
                        // Secure the connection by negotiating TLS
                        connection.proceedTLSReceived();
                        // Reset the state of the parser since a new stream element is going
                        // to be sent by the server
                        resetParser();
                    }
                    else if (parser.getName().equals("failure")) {
                        String namespace = parser.getNamespace(null);
                        if ("urn:ietf:params:xml:ns:xmpp-tls".equals(namespace)) {
                            // TLS negotiation has failed. The server will close the connection
                            throw new Exception("TLS negotiation has failed");
                        }
                        else if ("http://jabber.org/protocol/compress".equals(namespace)) {
                            // Stream compression has been denied. This is a recoverable
                            // situation. It is still possible to authenticate and
                            // use the connection but using an uncompressed connection
                            connection.streamCompressionDenied();
                        }
                        else {
                            // SASL authentication has failed. The server may close the connection
                            // depending on the number of retries
                            final Failure failure = PacketParserUtils.parseSASLFailure(parser);
                            processPacket(failure);
                            connection.getSASLAuthentication().authenticationFailed();
                        }
                    }
                    else if (parser.getName().equals("challenge")) {
                        // The server is challenging the SASL authentication made by the client
                        String challengeData = parser.nextText();
                        processPacket(new Challenge(challengeData));
                        connection.getSASLAuthentication().challengeReceived(challengeData);
                    }
                    else if (parser.getName().equals("success")) {
                        processPacket(new Success(parser.nextText()));
                        // We now need to bind a resource for the connection
                        // Open a new stream and wait for the response
                        connection.packetWriter.openStream();
                        // Reset the state of the parser since a new stream element is going
                        // to be sent by the server
                        resetParser();
                        // The SASL authentication with the server was successful. The next step
                        // will be to bind the resource
                        connection.getSASLAuthentication().authenticated();
                    }
                    else if (parser.getName().equals("compressed")) {
                        // Server confirmed that it's possible to use stream compression. Start
                        // stream compression
                        connection.startStreamCompression();
                        // Reset the state of the parser since a new stream element is going
                        // to be sent by the server
                        resetParser();
                    }
                }
                else if (eventType == XmlPullParser.END_TAG) {
                    if (parser.getName().equals("stream")) {
                        // Disconnect the connection
                        connection.disconnect();
                    }
                }
                eventType = parser.next();
            } while (!done && eventType != XmlPullParser.END_DOCUMENT && thread == readerThread);
        }
        catch (Exception e) {
            if (!done) {
                // Close the connection and notify connection listeners of the
                // error.
                notifyConnectionError(e);
            }
        }
    }

    /**
     * Releases the connection ID lock so that the thread that was waiting can resume. The
     * lock will be released when one of the following three conditions is met:<p>
     *
     * 1) An opening stream was sent from a non XMPP 1.0 compliant server
     * 2) Stream features were received from an XMPP 1.0 compliant server that does not support TLS
     * 3) TLS negotiation was successful
     *
     */
    synchronized private void releaseConnectionIDLock() {
        notify();
    }

    /**
     * Processes a packet after it's been fully parsed by looping through the installed
     * packet collectors and listeners and letting them examine the packet to see if
     * they are a match with the filter.
     *
     * @param packet the packet to process.
     */
    private void processPacket(Packet packet) {
        if (packet == null) {
            return;
        }

        // Loop through all collectors and notify the appropriate ones.
        for (PacketCollector collector: connection.getPacketCollectors()) {
            collector.processPacket(packet);
        }

        // Deliver the incoming packet to listeners.
        listenerExecutor.submit(new ListenerNotification(packet));
    }

    private void parseFeatures(XmlPullParser parser) throws Exception {
        boolean startTLSReceived = false;
        boolean startTLSRequired = false;
        boolean done = false;
        while (!done) {
            int eventType = parser.next();

            if (eventType == XmlPullParser.START_TAG) {
                if (parser.getName().equals("starttls")) {
                    startTLSReceived = true;
                }
                else if (parser.getName().equals("mechanisms")) {
                    // The server is reporting available SASL mechanisms. Store this information
                    // which will be used later while logging (i.e. authenticating) into
                    // the server
                    connection.getSASLAuthentication()
                            .setAvailableSASLMethods(PacketParserUtils.parseMechanisms(parser));
                }
                else if (parser.getName().equals("bind")) {
                    // The server requires the client to bind a resource to the stream
                    connection.getSASLAuthentication().bindingRequired();
                }
                else if(parser.getName().equals("ver")){
                	connection.getConfiguration().setRosterVersioningAvailable(true);
                }
                else if(parser.getName().equals("c")){
                	String node = parser.getAttributeValue(null, "node");
                	String ver = parser.getAttributeValue(null, "ver");
                	String capsNode = node+"#"+ver;
                	connection.getConfiguration().setCapsNode(capsNode);
                }
                else if (parser.getName().equals("session")) {
                    // The server supports sessions
                    connection.getSASLAuthentication().sessionsSupported();
                }
                else if (parser.getName().equals("compression")) {
                    // The server supports stream compression
                    connection.setAvailableCompressionMethods(PacketParserUtils.parseCompressionMethods(parser));
                }
                else if (parser.getName().equals("register")) {
                    connection.getAccountManager().setSupportsAccountCreation(true);
                }
            }
            else if (eventType == XmlPullParser.END_TAG) {
                if (parser.getName().equals("starttls")) {
                    // Confirm the server that we want to use TLS
                    connection.startTLSReceived(startTLSRequired);
                }
                else if (parser.getName().equals("required") && startTLSReceived) {
                    startTLSRequired = true;
                }
                else if (parser.getName().equals("features")) {
                    done = true;
                }
            }
        }

        // If TLS is required but the server doesn't offer it, disconnect
        // from the server and throw an error. First check if we've already negotiated TLS
        // and are secure, however (features get parsed a second time after TLS is established).
        if (!connection.isSecureConnection()) {
            if (!startTLSReceived && connection.getConfiguration().getSecurityMode() ==
                    ConnectionConfiguration.SecurityMode.required)
            {
                throw new XMPPException("Server does not support security (TLS), " +
                        "but security required by connection configuration.",
                        new XMPPError(XMPPError.Condition.forbidden));
            }
        }
        
        // Release the lock after TLS has been negotiated or we are not insterested in TLS
        if (!startTLSReceived || connection.getConfiguration().getSecurityMode() ==
                ConnectionConfiguration.SecurityMode.disabled)
        {
            releaseConnectionIDLock();
        }
    }

    /**
     * A runnable to notify all listeners of a packet.
     */
    private class ListenerNotification implements Runnable {

        private Packet packet;

        public ListenerNotification(Packet packet) {
            this.packet = packet;
        }

        public void run() {
            for (ListenerWrapper listenerWrapper : connection.recvListeners.values()) {
                try {
                    listenerWrapper.notifyListener(packet);
                } catch (RuntimeException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
