package org.jivesoftware.smack;

import java.util.List;

/**
 * This is an interface for persistent roster storage needed to implement XEP-0237
 * @author Till Klocke
 *
 */

public interface RosterStorage {
	
	/**
	 * This method returns a List object with all RosterEntries contained in this store.
	 * @return List object with all entries in local roster storage
	 */
	public List<RosterEntry> getAllRosterEntries();
	/**
	 * This method returns the RosterEntry which belongs to a specific user.
	 * @param bareJid The bare JID of the RosterEntry
	 * @return The RosterEntry which belongs to that user
	 */
	public RosterEntry getRosterEntry(String bareJid);
	/**
	 * Returns the number of entries in this roster store
	 * @return the number of entries
	 */
	public int getEntryCount();
	/**
	 * This method returns the RosterGroup which belongs to the specific group name
	 * @param groupName The group name
	 * @return the RosterGroup
	 */
	public RosterGroup getRosterGroup(String groupName);
	/**
	 * This method returns a List of all roster groups in this store
	 * @return a List object containing all RosterGroups
	 */
	public List<RosterGroup> getAllRosterGroups();
	/**
	 * This method returns the number of roster groups in this store.
	 * @return The number of roster groups
	 */
	public int getGroupCount();
	/**
	 * This methos returns the version number as specified by the "ver" attribute
	 * of the local store. Should return an emtpy string if store is empty.
	 * @return local roster version
	 */
	public String getRosterVersion();
	/**
	 * This method stores a new RosterEntry in this store or overrides an existing one.
	 * If ver is null an IllegalArgumentException should be thrown.
	 * @param entry the entry to save
	 * @param ver the version this roster push contained
	 */
	public void addEntry(RosterEntry entry, String ver);
	/**
	 * Create a new RosterGroup in this store
	 * @param group the RosterGroup to store
	 */
	//public void addGroup(RosterGroup group);
	/**
	 * Removes an entry from the persistent storage
	 * @param bareJid The bare JID of the entry to be removed
	 */
	public void removeEntry(String bareJid);
	/**
	 * Update an entry which has been modified locally
	 * @param entry the entry to be updated
	 */
	public void updateLocalEntry(RosterEntry entry);
	/**
	 * Return a specific roster entry identified by the bare JID
	 * @param bareJid The bare JID of the entry to retrieve
	 * @return
	 */
	public RosterEntry getEntry(String bareJid);
}
