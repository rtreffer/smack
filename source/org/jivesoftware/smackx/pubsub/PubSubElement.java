package org.jivesoftware.smackx.pubsub;

import java.util.Collections;
import java.util.List;

import org.jivesoftware.smack.packet.PacketExtension;
import org.jivesoftware.smackx.pubsub.packet.PubSubNamespace;

/**
 * Represents the packet extension used in messages.
 * The embedded event information, which is specific to the event type,
 * can be retrieved by the {@link #getExtension()} method.
 */
public class PubSubElement implements EmbeddedPacketExtension
{
	private List<PacketExtension> extensions = Collections.emptyList();
	
	public PubSubElement(List<PacketExtension> extensionList)
	{
		extensions = extensionList;
	}

	public List<PacketExtension> getExtensions()
	{
		return extensions;
	}

	public NodeExtension getExtension()
	{
		return (NodeExtension) extensions.get(0);
	}

	public String getElementName()
	{
		return "pubsub";
	}

	public String getNamespace()
	{
		return PubSubNamespace.BASIC.getXmlns();
	}

	public String toXML()
	{
		StringBuilder builder = new StringBuilder();
		builder.append("<");
		builder.append(getElementName());
		builder.append(" xmlns='");
		builder.append(getNamespace());
		builder.append("'>");
		for (PacketExtension extension : extensions)
			builder.append(extension.toXML());
		builder.append("</");
		builder.append(getElementName());
		builder.append(">");
		return builder.toString();
	}
}
