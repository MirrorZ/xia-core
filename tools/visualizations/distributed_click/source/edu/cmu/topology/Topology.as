﻿package edu.cmu.topology {
	import flash.display.*;
	import flash.events.*;
	import flash.net.*;
	import flash.utils.Dictionary;
	import edu.cmu.networkelements.*;
	
	public class Topology {
		
		// Constants:
		// Public Properties:
		// Private Properties:
		private var elementsByID:Dictionary;
		private var last:int = 0; // for testing; TODO: remove

	
		// Initialization:
		public function Topology() {
			elementsByID = new Dictionary();
		}
	
		// Public Methods:
		public function GetElementsByID():Dictionary {
			return elementsByID;
		}
		
		public function Update(connectionsString:String):void {
			var newDict:Dictionary = StringToDictionary(connectionsString);
			//var newDict:Dictionary = GetTestTopology();
			
			// Merge new dictionary into old one
			// 1) Add any new elements to the existing dictionary
			for (var newElementID:String in newDict) {
				if (elementsByID[newElementID] == null) {
					elementsByID[newElementID] = newDict[newElementID].Copy();  // make a NEW copy with same name
				}
			}

			// 2) Remove existing elements not in new topology
			for (var oldElementID:String in elementsByID) {

				if (newDict[oldElementID] == null) {
					elementsByID[oldElementID].DisconnectAllPorts();
					elementsByID[oldElementID].parent.removeChild(elementsByID[oldElementID]);
					elementsByID[oldElementID] = null;
					delete elementsByID[oldElementID];
				}
			}

			// 3) Update connections for remaining elements
			//    Loop through NEW elements; check corresponding old one and make sure each port is connected to the right element
			for (var newElementID:String in newDict) {
				var oldElement:NetworkElement = elementsByID[newElementID];
				if (oldElement == null) {
					trace("ERROR: Topology:Update: oldElement should not be null");
					continue;
				}
				
				oldElement.UpdateConnections(newDict[newElementID], elementsByID, newDict);
			}
			
		}
		
		// Protected Methods:
		private function StringToDictionary(connectionsString:String) : Dictionary {
			
			var newElementsByID:Dictionary = new Dictionary();
			
			//var connections:Vector.<Array> = Vector.<Array>(connectionsString.split("\n").map(splitCommas));
			var connections:Array = connectionsString.split("\n").map(splitCommas);
			var localPorts:Dictionary = new Dictionary();  // holds a dictionary for each HID mapping remote HIDs to local ports

			// First pass through makes a NetworkElement for each HID (and the IP cloud)
			for each (var connection:Array in connections)
			{
				if (connection.length != 6) {continue;} // TODO: make sure this works with IP routes
				var hid:String = connection[2];
				var name:String = connection[0];
				
				if (newElementsByID[hid] != null) { continue; }
				
				var element:NetworkElement;
				if (name.indexOf("router") >= 0) {    // TODO: this is a hack
					element = new edu.cmu.networkelements.Router(hid, name, 4);
				} else if (name.indexOf("server") >= 0 ||
						   name.indexOf("controller") >= 0) {
					element = new edu.cmu.networkelements.Server(hid, name);
				} else {
					element = new edu.cmu.networkelements.Host(hid, name);
				}
				
				newElementsByID[hid] = element;
				localPorts[hid] = new Dictionary();  // maps remote HIDs to local ports

			}
			newElementsByID["IP"] = new edu.cmu.networkelements.Cloud("IP", "IP");
			
			// Second pass deals with connections
			var showIPCloud:Boolean = false;
			for each (var connection:Array in connections) 
			{
				if (connection.length != 6) {continue;} // TODO: make sure this works with IP routes

				var hid:String = connection[2];
				
				var kind:String = connection[4];
				var localPort:int = int(connection[3]);
				var nextHID:String = connection[5];

				if (kind == "XID") 
				{
					localPorts[hid][nextHID] = localPort;
					if (localPorts[nextHID] != null && localPorts[nextHID][hid] != null) 
					{ 
						// We have both of the ports we need, so add the connection
						var remotePort:int = localPorts[nextHID][hid];
						newElementsByID[hid].ConnectElementToPort(newElementsByID[nextHID], localPort, remotePort);
					}
				} 
				else if (kind == "IP")
				{
					if (nextHID == "-") {
						showIPCloud = true;
						newElementsByID[hid].ConnectElementToPort(newElementsByID["IP"], localPort, -1);
					}
				}
			}
			
			// Don't draw IP cloud on screen if nothing's connected to it
			if (!showIPCloud) {
				delete newElementsByID["IP"];
			}
			
			return newElementsByID;
		}
		
		private function splitCommas(item:*, index:int, array:Array):Array {
			return String(item).split(",");
		}
		
		
		private function JsonToDictionary(devicesJSON:Object) : Dictionary {
			
			var newElementsByID:Dictionary = new Dictionary();
			
			// First pass through makes a NetworkElement for each HID (and the IP cloud)
			for (var device:String in devicesJSON)
			{
				var hid:String = devicesJSON[device]["hid"];
				var element:NetworkElement;
				if (hid.charAt(4) == '0') {    // TODO: this is a hack
					element = new edu.cmu.networkelements.Host(hid, "edu.cmu.networkelements.Host Name");
				} else if (hid.charAt(4) == '2') {
					element = new edu.cmu.networkelements.Router(hid, "edu.cmu.networkelements.Router Name", 4);
				}
				
				newElementsByID[hid] = element;
			}
			newElementsByID["IP"] = new edu.cmu.networkelements.Cloud("IP", "IP");
			
			// Second pass deals with connections
			var localPorts:Dictionary = new Dictionary();  // holds a dictionary for each HID
			for (var device:String in devicesJSON)
			{
				var hid:String = devicesJSON[device]["hid"];
				var routes:Object = devicesJSON[device]["routes"];
				
				localPorts[hid] = new Dictionary();  // maps remote HIDs to local ports
				
				for (var i:Object in routes) 
				{
					var kind:String = routes[i]["kind"];
					var localPort:int = int(routes[i]["port"]);
					var nextHID:String = routes[i]["next"];

					if (kind == "XID") 
					{
						localPorts[hid][nextHID] = localPort;
						if (localPorts[nextHID] != null) 
						{ 
							// We have both of the ports we need, so add the connection
							var remotePort:int = localPorts[nextHID][hid];
							newElementsByID[hid].ConnectElementToPort(newElementsByID[nextHID], localPort, remotePort);
						}
					} 
					else if (kind == "IP")
					{
						if (nextHID == "") {
							newElementsByID[hid].ConnectElementToPort(newElementsByID["IP"], localPort, -1);
						}
					}
				}
			}
			
			return newElementsByID;
		}
		
		private function GetTestTopology():Dictionary {
			var newDict = new Dictionary();
			var host0 = new edu.cmu.networkelements.Host("edu.cmu.networkelements.Host0", "edu.cmu.networkelements.Host0 Name");
			var host1 = new edu.cmu.networkelements.Host("edu.cmu.networkelements.Host1", "edu.cmu.networkelements.Host1 Name");
			var host2 = new edu.cmu.networkelements.Host("edu.cmu.networkelements.Host2", "edu.cmu.networkelements.Host2 Name");
			var router0 = new edu.cmu.networkelements.Router("edu.cmu.networkelements.Router0", "edu.cmu.networkelements.Router 0 Name", 4);
			var router1 = new edu.cmu.networkelements.Router("edu.cmu.networkelements.Router1", "edu.cmu.networkelements.Router 1 Name", 4);
			var cloud = new edu.cmu.networkelements.Cloud("IP", "IP");
			
			if (last == 0) {
				host0.ConnectElementToPort(router1, 0, 2);
				last = 1;
			} else {
				host0.ConnectElementToPort(router0, 0, 3);
				last = 0;
			}
			router0.ConnectElementToPort(router1, 1, 1);
			router0.ConnectElementToPort(cloud, 2, 2);
			router1.ConnectElementToPort(host1, 0, 0);
			host2.ConnectElementToPort(cloud, 0, 5);
			
			newDict["edu.cmu.networkelements.Host0"] = host0;
			newDict["edu.cmu.networkelements.Host1"] = host1;
			newDict["edu.cmu.networkelements.Host2"] = host2;
			newDict["edu.cmu.networkelements.Router0"] = router0;
			newDict["edu.cmu.networkelements.Router1"] = router1;
			newDict["IP"] = cloud;
			
			return newDict;
		}
	}
}