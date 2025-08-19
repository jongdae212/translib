////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2023 Celestica, Inc.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

//+build ClsBuildAdv

package translib

import (
    "encoding/json"
    "errors"
    "strconv"
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"

    log "github.com/golang/glog"
    "github.com/openconfig/ygot/ygot"
)


const (
    VXLAN_PROFILE              = "vxlan_profile"
    NVO_ENTRY_KEY              = "nvo1"
    SOURCE_VTEP_FIELD          = "source_vtep"
    REMOTE_VTEP_FIELD          = "remote_vtep"
    DST_IP_FIELD               = "dst_ip"
    SOURCE_IP_FIELD            = "src_ip"
    VTEP_MAC                   = "vtep_mac"
    VLAN_FIELD                 = "vlan"
    VNI_FIELD                  = "vni"
    MAC_TYPE                   = "type"
    TUNNEL_STATUS_FIELD        = "operstatus"
    TUNNEL_SOURCE_FIELD        = "tnl_src"
    FLEX_CTR_TUN_ENTRY         = "TUNNEL"
    DEVICE_METADATA_ENTRY      = "localhost"
    TUN_CTR_STATUS             = "FLEX_COUNTER_STATUS"
    RATE_INTERVAL              = "POLL_INTERVAL"
    EVPN_SRC                   = "EVPN"
    DEFAULT_RATE_INTERVAL      = 10
    MS_IN_SECONDS              = 1000
    CONFIG_DB_SEPARATOR        = "|"
    APPL_DB_SEPARATOR          = ":"
    KERNEL_ONLY_CONFIG_FIELD   = "kernel_only_config"
)

// Get the sonic tunnel status from Openconfig tunnel status
func getOCTunnelStatusFromSonicTunnelStatus(statusStr string) (ocbinds.E_OpenconfigVxlanCls_TunnelStatus) {
    var TUN_STATUS_MAP = map[string]ocbinds.E_OpenconfigVxlanCls_TunnelStatus {
        "up":ocbinds.OpenconfigVxlanCls_TunnelStatus_UP,
        "down":ocbinds.OpenconfigVxlanCls_TunnelStatus_DOWN,
    }

    if result, found := TUN_STATUS_MAP[statusStr]; found {
        return result
    }
    return ocbinds.OpenconfigVxlanCls_TunnelStatus_UNSET
}

// Get the sonic tunnel source from Openconfig tunnel source
func getOCTunnelSrcFromSonicTunnelSrc(src string) (ocbinds.E_OpenconfigVxlanCls_TunnelType) {
    var TUN_SRC_MAP = map[string]ocbinds.E_OpenconfigVxlanCls_TunnelType {
        "EVPN":ocbinds.OpenconfigVxlanCls_TunnelType_DYNAMIC,
        "CLI":ocbinds.OpenconfigVxlanCls_TunnelType_STATIC,
    }

    if result, found := TUN_SRC_MAP[src]; found {
        return result
    }
    return ocbinds.OpenconfigVxlanCls_TunnelType_UNSET
}

// Get the sonic learned mac type from Openconfig learned mac type
func getOCPeerVtepMacTypeFromSonicVtepMacType(macStr string) (ocbinds.E_OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac_Type) {
    var VTEP_MAC_TYPE_MAP = map[string]ocbinds.E_OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac_Type {
        "static":ocbinds.OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac_Type_STATIC,
        "dynamic":ocbinds.OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac_Type_DYNAMIC,
    }

    if result, found := VTEP_MAC_TYPE_MAP[macStr]; found {
        return result
    }
    return ocbinds.OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac_Type_UNSET
}

// Translation Helper fn to convert tunnel counter polling interval DB info to Internal DS
func (app *VxlanApp) getTunCtrPollIntFromDB(d *db.DB) error {
    var err error

    tunFlexCtrInfo,err := d.GetEntry(app.tunnelFlexCountrTblTs,asKey(FLEX_CTR_TUN_ENTRY))
    if err != nil {
        log.Error("Fetching flex-counter tunnel table entry failed. Tunnel counter is disabled")
        return err
    }
    app.tunnelFlexCtrMap[FLEX_CTR_TUN_ENTRY] = dbEntry{entry: tunFlexCtrInfo}
    return err
}

// Translation Helper fn to convert tunnel name to OID info to Internal DS
func (app *VxlanApp) getTunnelOidMapForCounters(d *db.DB) error {
    var err error
    tunCountInfo, err := d.GetMapAll(app.tunnelOidCountrTblTs)
    if err != nil {
        log.Error("Tunnel-OID (Counters) get for all the tunnels failed!")
        return err
    }
    log.Infof("tunCountInfo: %v", tunCountInfo)
    if tunCountInfo.IsPopulated() {
        app.tunnelOidMap.entry = tunCountInfo
    } else {
        return errors.New("Get for OID info from all the tunnels from Counters DB failed!")
    }
    return err
}

func (app *VxlanApp) getTunnelCounterInfoFromDB(d *db.DB, tunnelName string, tunnelKey db.Key) error {
    var err error

    if len(tunnelName) > 0 {
        oid := app.tunnelOidMap.entry.Field[tunnelName]
        log.Infof("OID : %s received for tunnel : %s", oid, tunnelName)

        // Get the statistics for the tunnel
        var tunStatKey db.Key
        tunStatKey.Comp = []string{oid}

        // Get the diff of both current counters and snapshot taken while clearing
        tunStatInfo, err := GetTblDiff(d,COUNTERS_TABLE,CLEAR_COUNTERS_TABLE,tunStatKey)
        if err != nil {
            tunStatInfo, err = d.GetEntry(app.tunnelCountrTblTs, tunStatKey)
            if err != nil {
                log.Errorf("Fetching stat for tunnel : %s failed!", tunnelName)
                return err
            }
        }
        app.tunnelStatMap[tunnelName] = dbEntry{entry: tunStatInfo}

        tunRateInfo,err := d.GetEntry(app.tunnelRatesTblTs,tunStatKey)
        if err != nil {
            log.Errorf("Fetching tunnel rates failed for key: %s",tunnelName)
            return err
        }
        app.tunnelRateMap[tunnelName] = dbEntry{entry: tunRateInfo}
    } else {
        log.Info("COUNTER-DB get for all tunnels interfaces name")
        log.Infof("tunnelOidMap.Field: %v", app.tunnelOidMap.entry.Field)
        for tunnelName := range app.tunnelOidMap.entry.Field {
            app.getTunnelCounterInfoFromDB(d, tunnelName, asKey(tunnelName))
        }
    }
    return err
}

func (app *IntfApp) handleVxlanIntfSipEntryDelete(d *db.DB, ifName string) ([]db.WatchKeys, error) {
    var keys []db.WatchKeys
    var mapKeys []db.Key
    var entry dbEntry
    var curr db.Value

    nodeInfo, err := getTargetNodeYangSchema(app.path.Path, (*app.ygotRoot).(*ocbinds.Device))
	if err != nil {
        log.Error("Failed to get target node")
        return keys, tlerr.InvalidArgs("Failed to get target node.")
    }

    // Fetch the vxlan interface config entry from DB
    entry.key = asKey(ifName)
    curr, err = getIntfFromDb(d, ifName)

    // Throw error if Vxlan interface not exists
    if err != nil {
        return keys, tlerr.NotFound("No such Vxlan interface config entry exists.")
    }

    // Throw error if vxlan vlan-vni map configs still exist
    mapKeys, _ = d.GetKeys(app.intfVxlanMapTs)
    if len(mapKeys) > 0 {
        log.Error("Vxlan vlan-vni map configs present. Please remove vlan vni map configs first")
        errStr := "Please delete all VLAN-VNI mappings."
        return keys, tlerr.InternalError{Format: errStr}
    }

    if nodeInfo.IsLeaf() {
        switch nodeInfo.Name {
        case "source-vtep-ip":
            tmp_curr := db.Value{Field: make(map[string]string)}
            tmp_curr.Field[SOURCE_IP_FIELD] = curr.Field[SOURCE_IP_FIELD]
            tmp_curr.Field[VTEP_MAC] = curr.Field[VTEP_MAC]
            entry.entry = tmp_curr
            entry.op = DELETE
            log.Infof("Deleting %s field from VXLAN_TUNNEL table entry",
                        SOURCE_IP_FIELD)
        default:
            log.Errorf("Removing %s is not supported.", nodeInfo.Name)
            return keys, tlerr.NotSupported("Removing '%s' is not supported.",
                                            nodeInfo.Name)
        }
    } else {
        log.Error("This yang type is not handled currently")
        return keys, tlerr.NotSupported("Yang type not supported")
    }

    entry.ts = app.intfVxlanTs
    log.Infof("Translated DB entry [op:%d][table:%s][key:%s]",
                            entry.op, entry.ts.Name, entry.key)
    app.ifVxlanMap[ifName] = entry

    return keys, err
}

func (app *IntfApp) deleteVxlanMapEntry(d *db.DB, ifName string, key db.Key) ([]db.WatchKeys, error) {
    var err error
    var keys []db.WatchKeys
    var curr db.Value
    var entry dbEntry

    curr, err = d.GetEntry(app.intfVxlanMapTs, key)
    if err != nil {
        log.Errorf("Error found on fetching Vxlan vlan vni map Intf:(%s,%s) info fromDB",
                        key.Get(0), key.Get(1))
        return keys, tlerr.NotSupportedError{Format: "No such vxlan vlan-vni map config entry exists.",
                                            Path: app.path.Path}
    }

    entry.key = key
    entry.op = DELETE
    entry.ts = app.intfVxlanMapTs
    entry.entry = curr
    log.Infof("Translated DB entry [op:%d][table:%s][key:%s]",
                entry.op, entry.ts.Name, entry.key)
    app.ifVxlanVlanVniMap[key.Get(1)] = entry
	return keys, err
}

func validateVlanMapConfig(d *db.DB, vlanId int, count int) ([]db.WatchKeys, error) {
    var err error
    var keys []db.WatchKeys

    if (count + vlanId -1) > DEF_MAX_VLANS_SUPPORTED {
        log.Error("Out-of-range vlan-ids are refered in vxlan map entry")
        errStr := "Vxlan map entry contains out of range vlan-ids"
        return keys, tlerr.InternalError{Format: errStr}
    }
    // Throw error, if any of the vlan interface given in the count not exist
    for it := 0; it < count; it++ {
        vlan := "Vlan"+strconv.FormatUint(uint64(vlanId+it),10)
        _, err = getIntfFromDb(d, vlan)

        if err != nil {
            errStr := vlan+ " interface not present"
            return keys, tlerr.InternalError{Format: errStr}
        }
    }
    return keys, err
}

func (app *IntfApp) handleVxlanIntfFieldsDelete(d *db.DB) ([]db.WatchKeys, error) {
    var err error
    var keys []db.WatchKeys
    var mapKeys []db.Key

    pathInfo :=  app.path
    log.Infof("Received Delete for path =%s template=%s vars=%v",
            pathInfo.Path, pathInfo.Template, pathInfo.Vars)
    ifName := pathInfo.Var("name")

    if isSubtreeRequest(pathInfo.Template, "/openconfig-interfaces:interfaces/interface{}/openconfig-vxlan-cls:vxlan-if/config/source-vtep-ip") {

        keys, err = app.handleVxlanIntfSipEntryDelete(d, ifName)
        if err != nil {
            return keys, err
        }
        //Delete "VXLAN_EVPN_NVO|nvo1" default entry after
        //removing SIP field from VXLAN_TUNNEL table.
        keys, err = app.handleVxlanNvoConfigToDB(d, DELETE, ifName)

    } else if isSubtreeRequest(pathInfo.Template, "/openconfig-interfaces:interfaces/interface{}/openconfig-vxlan-cls:vxlan-if/config/vni-instances/vni-instance{}") {

        log.Info("Delete a specific vni vlan map config request")
        if false == pathInfo.HasVar("vni-id") && false == pathInfo.HasVar("vlan-id") && false == pathInfo.HasVar("map-count"){
            return keys, tlerr.InvalidArgs("Map key is  missing.")
        }

        vni, _ := pathInfo.IntVar("vni-id")
        vlan, _ := pathInfo.IntVar("vlan-id")
        count, _ := pathInfo.IntVar("map-count")

        log.Infof("vni = %d vlan = %d count = %d", vni, vlan, count)

        keys, err = validateVlanMapConfig(d, vlan, count)
        if err != nil {
           return keys, err
        }

        for it := 0 ; it < count; it++ {
            vlanStr := strconv.FormatUint(uint64(vlan+it),10)
            vniStr := strconv.FormatUint(uint64(vni+it), 10)
            keyStr := getVxlanMapEntryKeyStrFromOCKey(vniStr, vlanStr)

		    keys, err = app.deleteVxlanMapEntry(d, ifName, asKey(ifName, keyStr))
            if err != nil {
                return keys, err
            }
        }

    } else if isSubtreeRequest(pathInfo.Template, "/openconfig-interfaces:interfaces/interface{}/openconfig-vxlan-cls:vxlan-if/config/vni-instances") || isSubtreeRequest(pathInfo.Template, "/openconfig-interfaces:interfaces/interface{}/openconfig-vxlan-cls:vxlan-if/config/vni-instances/vni-instance") {

        log.Info("Delete all vni vlan map configs request")
        mapKeys, _ = d.GetKeys(app.intfVxlanMapTs)
        for _, key := range mapKeys {
            log.Infof("Delete all vlan vni maps in vxlan intf key:(%s, %s)", key.Get(0), key.Get(1))

            keys, err = app.deleteVxlanMapEntry(d, ifName, key)
            if err != nil {
                return keys, err
            }
        }

    } else {
        err = tlerr.NotSupported("Unsupported attribute in delete operation")
    }
    return keys, err
}

func getVxlanAttr(vxlanMap map[string]dbEntry, name string, attr string) (string, error) {
    var ok bool = false
    var entry dbEntry

    entry, ok = vxlanMap[name]
    if ok {
        data := entry.entry
        if val, ok := data.Field[attr]; ok {
            return val, nil
        }
    }
    return "", tlerr.NotFound("Attr " + attr + " doesn't exist in Vxlan Intf table Map!")
}

func (app *VxlanApp) getVxlanIfInfoFromDB(d *db.DB, ifName string, vxlanIfKey db.Key) error {
    var err error

    if len(ifName) > 0 {
        // Fetching DB data for a specific vxlan interface
        log.Infof("Updating Vxlan Intf:%s info from CFG-DB to Internal DS", ifName)
        vxlanInfo, err := d.GetEntry(app.intfVxlanTs, vxlanIfKey)
        if err != nil {
            log.Errorf("Error found on fetching vxlan intf :%s info from CFG-DB", ifName)
            err = tlerr.NotFound("No such vxlan intf exists.")
            return err
        }
        if vxlanInfo.IsPopulated() {
            app.ifVxlanMap[ifName] = dbEntry{entry: vxlanInfo}
        } else {
            return errors.New("Populating vxlan intf info for " + ifName + "failed")
        }
    } else {
        log.Info("CFG-DB get for all vxlan interfaces")
        keys, _ := d.GetKeys(app.intfVxlanTs)
        for _, key := range keys {
            app.getVxlanIfInfoFromDB(d, key.Get(0), key)
        }
    }
    return err
}


func (app *VxlanApp) getVxlanNvoInfoFromDB(d *db.DB, nvoName string, nvoKey db.Key) error {
	var err error
    if len(nvoName) > 0 {
        log.Infof("Updating Vxlan nvo:%s info from CFG-DB to Internal DS", nvoName)
        nvoInfo, err := d.GetEntry(app.intfVxlanNvoTs, nvoKey)
        if err != nil {
            log.Errorf("Error found on fetching vxlan nvo :%s info from CFG-DB", nvoName)
            return err
        }
        if nvoInfo.IsPopulated() {
            app.ifVxlanNvoMap[nvoName] = dbEntry{entry: nvoInfo}
        } else {
            return errors.New("Populating nvo intf info for " + nvoName + "failed")
        }
    } else {
        log.Info("CFG-DB get for all Nvo instances")
        keys, _ := d.GetKeys(app.intfVxlanNvoTs)
	    for _, key := range keys {
            app.getVxlanNvoInfoFromDB(d, key.Get(0), key)
        }
	}
	return err
}

func (app *VxlanApp) getVxlanInfoFromInternalMap(ifName *string, vxlanInfo *ocbinds.OpenconfigVxlanCls_Vxlan_State) {
	// Populate vtep-name, src-ip fields
	if _, ok := app.ifVxlanMap[*ifName]; ok {
		vtepName := new(string)
		*vtepName = *ifName
		vxlanInfo.Vtep = vtepName
    }

    val, _ := getVxlanAttr(app.ifVxlanMap, *ifName, SOURCE_IP_FIELD)
    if len(val) > 0 {
        ip := new(string)
        *ip = val
        vxlanInfo.SourceIp = ip
        log.Info("vxlanInfo.SourceIp=", val)
    }

    val1, _ := getVxlanAttr(app.ifVxlanMap, *ifName, VTEP_MAC)
    if len(val1) > 0 {
        mac := new(string)
        *mac = val1
        vxlanInfo.VtepMac = mac
        log.Info("vxlanInfo.VtepMac=", val1)
    }

	// Populate nvo name
	for nvoKey, _ := range app.ifVxlanNvoMap {
        val, _ := getVxlanAttr(app.ifVxlanNvoMap, nvoKey, SOURCE_VTEP_FIELD)
        if len(val) > 0 {
            // populate nvo field only if nvo entry's source_vtep
            // field matches with ifName
            if *ifName == val {
                nvo := new(string)
                *nvo = nvoKey
                vxlanInfo.Nvo = nvo
                log.Info("vxlanInfo.Nvo=",nvoKey)
            }
        }
    }

	// Populate src-intf name
	if vxlanInfo.SourceIp != nil {
		// Fetch the Loopback interface name configured with the vtep's src_ip
		sipExist, loIfName := isSameIpAlreadyConfiguredOnLoIntf(app.appDB, *vxlanInfo.SourceIp)
		if sipExist {
			srcIntf := new(string)
			*srcIntf = loIfName
			vxlanInfo.SourceInterface = srcIntf
			log.Info("vxlanInfo.SourceInterface=", loIfName)
		}
	}
}

func (app *VxlanApp) getVxlanStateSpecificAttr(targetUriPath string,
							ocStVal *ocbinds.OpenconfigVxlanCls_Vxlan_State) (bool, error) {
    var e error
    var val string

    switch targetUriPath {
	case "/openconfig-vxlan-cls:vxlan/state/vtep":
		for vtepName, _ := range app.ifVxlanMap {
			if _, ok := app.ifVxlanMap[vtepName]; ok {
				vtep := new(string)
				*vtep = vtepName
				ocStVal.Vtep = vtep
				return true, nil
			}
		}

	case "/openconfig-vxlan-cls:vxlan/state/source-ip":
		for vtepName, _ := range app.ifVxlanMap {
			val, e = getVxlanAttr(app.ifVxlanMap, vtepName, SOURCE_IP_FIELD)
			if len(val) > 0 {
				ip := new(string)
				*ip = val
				ocStVal.SourceIp = ip
				log.Info("ocStVal.SourceIp=", val)
				return true, nil
			}
		}
        return true, e

	case "/openconfig-vxlan-cls:vxlan/state/nvo":
		for nvoName, _ := range app.ifVxlanNvoMap {
			val, e = getVxlanAttr(app.ifVxlanNvoMap, nvoName, SOURCE_VTEP_FIELD)
			if len(val) > 0 {
				nvo := new(string)
				*nvo = nvoName
				ocStVal.Nvo = nvo
				log.Info("ocStVal.Nvo=",nvoName)
				return true, nil
			}
		}
        return true, e

	case "/openconfig-vxlan-cls:vxlan/state/source-interface":
		for vtepName, _ := range app.ifVxlanMap {
			val, e = getVxlanAttr(app.ifVxlanMap, vtepName, SOURCE_IP_FIELD)
			if len(val) > 0 {
				// Fetch the Loopback interface name configured with the vtep's src_ip
				sipExist, loIfName := isSameIpAlreadyConfiguredOnLoIntf(app.appDB, val)
				if sipExist {
					srcIntf := new(string)
					*srcIntf = loIfName
					ocStVal.SourceInterface = srcIntf
					log.Info("ocStVal.SourceInterface=", loIfName)
					return true, nil
				}
			}
		}
        return true, e

	default:
		log.Infof(targetUriPath + " - Unsupported attribute")
    }
    return false, nil
}

func (app *VxlanApp)getVxlanVtepName(d *db.DB) string {
    var err error

    err = app.getVxlanIfInfoFromDB(d, "", db.Key{})
    if err == nil {
        for ifName, _ := range app.ifVxlanMap {
            return ifName
        }
    }
    return ""
}

func (app *VxlanApp)constructVxlanIntfOCInfo(targetUriPath string,
						vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                        dbs [db.MaxDB]*db.DB, isRootObj bool) (GetResponse, error) {
    var err error
    var payload []byte

    // Filling Vxlan interface Info to internal DS
    app.appDB = dbs[db.ConfigDB]
    err = app.getVxlanIfInfoFromDB(app.appDB, "", db.Key{})
    if err != nil {
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }
    err = app.getVxlanNvoInfoFromDB(app.appDB, "", db.Key{})
    if err != nil {
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }
    // Check if the request is for a specific attribute in vxlan state container
    ocState := &ocbinds.OpenconfigVxlanCls_Vxlan_State{}
    ok, e :=  app.getVxlanStateSpecificAttr(targetUriPath, ocState)
    if ok {
        if e != nil {
            return GetResponse{Payload: payload, ErrSrc: AppErr}, e
        }
        payload, err = dumpIetfJson(ocState)
        if err == nil {
            return GetResponse{Payload: payload}, err
        } else {
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
    }

    vxlanState := vxlanObj.State
    ygot.BuildEmptyTree(vxlanState)
    for ifName, _ := range app.ifVxlanMap {
        log.Info("ifName = ", ifName)
        app.getVxlanInfoFromInternalMap(&ifName, vxlanState)
    }
    // Check if the request is for vxlan state container
    if *app.ygotTarget == vxlanState || isRootObj == true {
        payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
    } else {
        log.Info("Not supported get type!")
        err = tlerr.NotSupported("Requested get-type not supported!")
    }
    if err != nil {
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }
    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp) getVlanVniMapInfoFromDB(d *db.DB, mapName string, mapKey db.Key) error {
    var err error

    if len(mapName) > 0 {
        // Fetching DB data for a specific vlan vni map
        log.Infof("Updating vlan-vni-map:%s info from CFG-DB to Internal DS", mapName)
        mapInfo, err := d.GetEntry(app.intfVxlanMapTs, mapKey)
        if err != nil {
            log.Errorf("Error found on fetching vlan-vni-map:%s info from CFG DB", mapName)
            err = tlerr.NotFound("No such vlan-vni map exists.")
            return err
        }
        if mapInfo.IsPopulated() {
            app.ifVxlanVlanVniMap[mapName] = dbEntry{entry: mapInfo}
        } else {
            return errors.New("Populating vlan-vni-map info for " + mapName + "failed")
        }
    } else {
        log.Info("CFG-DB get for all vlan-vni-maps")
        keys, _ := d.GetKeys(app.intfVxlanMapTs)
        for _, key := range keys {
            app.getVlanVniMapInfoFromDB(d, key.Get(1), key)
        }
    }
    return err
}

func getVlanVniFromVxlanMapKey(key string)(uint32, uint16) {
	var vni int
	var vlan int

    mapKeys :=  strings.Split(key, "_")
	if len(mapKeys) == 3 {
		vni, _ = strconv.Atoi(mapKeys[1])
		vlanStr := strings.Trim(mapKeys[2], "Vlan")
		vlan, _ = strconv.Atoi(vlanStr)
	}
    return uint32(vni), uint16(vlan)
}

func getVxlanPeerEntryKeyStrFromOCKey(vlan string, ipOrMac string) (string) {
    return vlan + "_" + ipOrMac
}

func getPeerAddrVlanFromVxlanPeerKey(key string) (string, uint16) {
    var vlan int

    mapKeys :=  strings.Split(key, "_")
    vlanStr := strings.Trim(mapKeys[0], "Vlan")
    vlan, _ = strconv.Atoi(vlanStr)

    return mapKeys[1], uint16(vlan)
}

func (app *VxlanApp) getVlanVniMapInfoFromInternalMap(mapName string, isPeerObj bool,
						peerMapInfo *ocbinds.OpenconfigVxlanCls_Vxlan_PeerVlanVniMaps_State_PeerVlanVniMap,
                        mapInfo *ocbinds.OpenconfigVxlanCls_Vxlan_VlanVniMaps_State_VlanVniMap) {
	var entry dbEntry
	var ok bool

    if isPeerObj {
        entry, ok = app.peerVniTableMap[mapName]
    } else {
        entry, ok = app.ifVxlanVlanVniMap[mapName]
    }

    // Handling the vlan vni map attributes
    if ok {
        mapData := entry.entry
        log.Info("Map name= ", mapName)

        if isPeerObj {
            ip := new(string)
            *ip, _ = getPeerAddrVlanFromVxlanPeerKey(mapName)
            peerMapInfo.PeerIp = ip
        }

        for mapAttr := range mapData.Field {
            switch mapAttr {
            case VNI_FIELD:
                vniStr := mapData.Get(mapAttr)
                vni, err := strconv.Atoi(vniStr)
                vniId := new(uint32)
                *vniId = uint32(vni)
                if err == nil {
                    if isPeerObj {
                        peerMapInfo.VniId = vniId
                        log.Infof("peerMapInfo.VniId=%d", *vniId)
                    } else {
                        mapInfo.VniId = vniId
                        log.Infof("mapInfo.VniId=%d", *vniId)
                    }
                }
            case VLAN_FIELD:
                vlanStr := mapData.Get(mapAttr)
                vlan, err := strconv.Atoi(strings.Trim(vlanStr, "Vlan"))
                vlanId := new(uint16)
                *vlanId = uint16(vlan)
                if err == nil {
                    if isPeerObj {
                        peerMapInfo.VlanId = vlanId
                        log.Infof("peerMapInfo.VlanId=%d",*vlanId)
                    } else {
                        mapInfo.VlanId = vlanId
                        log.Infof("mapInfo.VlanId=%d",*vlanId)
                    }
                }

            default:
                log.Info("Not a valid attribute=",mapAttr)
            }
        }
    }
}

func (app *VxlanApp)constructVlanVniMapOCInfo(vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                                   dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
    var resp GetResponse
    pathInfo := app.path

    if vxlanObj.VlanVniMaps == nil {
        err = tlerr.NotSupported("VlanVniMaps container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    if vxlanObj.VlanVniMaps.State == nil {
        err = tlerr.NotSupported("VlanVniMaps state container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    // Get request for a specific vlan-vni map
    if vxlanObj.VlanVniMaps.State.VlanVniMap != nil && len(vxlanObj.VlanVniMaps.State.VlanVniMap) > 0 &&
                pathInfo.HasVar("vni-id") == true && pathInfo.HasVar("vlan-id") == true {
        log.Info("Get specific vlan-vni map config request!")

        vni := pathInfo.Var("vni-id")
        vlan := pathInfo.Var("vlan-id")
        log.Infof("Vni-id = %s vlan-id = %s", vni, vlan)
        vniInt, _ := strconv.Atoi(vni)
		vlanInt, _ := strconv.Atoi(vlan)

        mapKey := getVxlanMapEntryKeyStrFromOCKey(vni, vlan)
        vtepName := app.getVxlanVtepName(dbs[db.ConfigDB])
		if vtepName == "" {
			err = tlerr.NotFound("No Vtep associated vlan-vni map exists.")
			return GetResponse{Payload: payload, ErrSrc: AppErr}, err
		}
        app.appDB = dbs[db.ConfigDB]

        // Filling Vlanvni map Info to internal DS
        err = app.getVlanVniMapInfoFromDB(app.appDB, mapKey, asKey(vtepName, mapKey))
        if err != nil {
			return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }

        ygot.BuildEmptyTree(vxlanObj.VlanVniMaps)
        ygot.BuildEmptyTree(vxlanObj.VlanVniMaps.State)

        mapOCKey := ocbinds.OpenconfigVxlanCls_Vxlan_VlanVniMaps_State_VlanVniMap_Key{VniId: uint32(vniInt), VlanId: uint16(vlanInt)}
        mapInfo := vxlanObj.VlanVniMaps.State.VlanVniMap[mapOCKey]
        ygot.BuildEmptyTree(mapInfo)

		app.getVlanVniMapInfoFromInternalMap(mapKey, false, nil, mapInfo)

        // Dump the contents, if get request is valid
        if *app.ygotTarget == mapInfo {
			payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
        } else {
            log.Info("Not supported get type!")
            err = tlerr.NotSupported("Requested get-type not supported!")
        }
        resp = GetResponse{Payload: payload}
    } else {
        log.Info("Get all vlan-vni-maps(without key) config request!")
        resp, err = app.constructVlanVniMapsOCInfo(vxlanObj, dbs)
    }
	return resp, err
}


func (app *VxlanApp)constructVxlanVrfVniMapsOCInfo(targetUriPath string,
    vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan, dbs [db.MaxDB]*db.DB) (GetResponse, error) {

    var err error
    var payload []byte
    app.configDB = dbs[db.ConfigDB]
	err = app.getVrfVniMapInfoFromDB(app.configDB)
    if err != nil {
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

	mapsInfo := vxlanObj.State
    ygot.BuildEmptyTree(mapsInfo)

    for vrfName, _ := range app.VxlanVrfVniMap {
        log.Info("vrfName = ", vrfName)
        VxlanVrfVniInfo, err := mapsInfo.NewVniVrf(vrfName)
        if err != nil {
            log.Errorf("Creation of vrf-vni map subtree for %s failed!", vrfName)
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
        ygot.BuildEmptyTree(VxlanVrfVniInfo)
        app.getVxlanVrfVniMapInfoFromInternalMap(vrfName,VxlanVrfVniInfo)
    }
    payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp) getVrfVniMapInfoFromDB(d *db.DB) error {
    var err error
    Vrftable, err := d.GetTable(app.VrfTs)
    if err != nil {
        log.Info("Vrf Table not found on configDB")
        return nil
    }
    keys, _ := Vrftable.GetKeys()
    for _, key := range keys {
        vrfinfo, err := Vrftable.GetEntry(key)
        if err != nil {
			log.Errorf("Failed to get VRF table entry %s",key)
			return nil
		}
        app.VxlanVrfVniMap[key.Get(0)] = dbEntry{entry: vrfinfo}
    }
    return err
}

func (app *VxlanApp) getVxlanVrfVniMapInfoFromInternalMap(vrfName string, VxlanVrfVniInfo *ocbinds.OpenconfigVxlanCls_Vxlan_State_VniVrf,) {

    // Handling vxlan vrf-vni attributes
    if entry,ok := app.VxlanVrfVniMap[vrfName]; ok {
        vrfData := entry.entry
        log.Info("Vrf name= ", vrfName)

        for vrfAttr := range vrfData.Field {
            log.Infof("vrfAttr = %s", vrfAttr)
            if vrfAttr == "vni" {
                if vni, err := strconv.Atoi(vrfData.Get(vrfAttr)); err == nil {
                    vniId := uint64(vni)
                    VxlanVrfVniInfo.VniMapVniId = &vniId
                    log.Infof("VxlanVrfVniInfo.VniMapVniId=%d", vniId)
                }
            } else {
                log.Infof("Not a valid attribute = %s", vrfAttr)
            }
        }
    }
}

func (app *VxlanApp)constructVlanVniMapsOCInfo(vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                                  dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte

    // Filling vlan-vni map Info to internal DS
    app.appDB = dbs[db.ConfigDB]
	err = app.getVlanVniMapInfoFromDB(app.appDB, "", db.Key{})

    if err != nil {
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    ygot.BuildEmptyTree(vxlanObj.VlanVniMaps)
	mapsInfo := vxlanObj.VlanVniMaps.State
    ygot.BuildEmptyTree(mapsInfo)

    for mapName, _ := range app.ifVxlanVlanVniMap {
        log.Info("mapName = ", mapName)
        vni, vlan := getVlanVniFromVxlanMapKey(mapName)
        oneMapInfo, err := mapsInfo.NewVlanVniMap(vni, vlan)
        if err != nil {
            log.Errorf("Creation of vlan-vni map subtree for %s failed!", mapName)
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
        ygot.BuildEmptyTree(oneMapInfo)
        app.getVlanVniMapInfoFromInternalMap(mapName, false, nil, oneMapInfo)
    }
    payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))

    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp) getPeerVlanVniMapInfoFromDB(d *db.DB, mapName string,
                                            mapKey db.Key) error {
    var err error

    if len(mapName) > 0 {
        // Fetching DB data for a specific peer vlan vni map
        log.Infof("Updating vlan-vni-map:%s from APPL_DB to Internal DS", mapName)
        mapInfo, err := d.GetEntry(app.peerVniAppTableTs, mapKey)
        if err != nil {
            log.Errorf("Error found on fetching peer-vlan-vni-map:%s info from APPL_DB", mapName)
            err = tlerr.NotFound("No such peer-vlan-vni map exists.")
            return err
        }
        if mapInfo.IsPopulated() {
            app.peerVniTableMap[mapName] = dbEntry{entry: mapInfo}
        } else {
            return errors.New("Populating peer-vlan-vni-map info for " + mapName + "failed")
        }
    } else {
        log.Info("DB get for all peer-vlan-vni-maps")
        keys, _ := d.GetKeys(app.peerVniAppTableTs)
        for _, key := range keys {
			peerMapName := getVxlanPeerEntryKeyStrFromOCKey(key.Get(0), key.Get(1))
            app.getPeerVlanVniMapInfoFromDB(d, peerMapName, key)
        }
    }
    return err
}

func (app *VxlanApp)constructPeerVlanVniMapsOCInfo(vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                                               dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte

    // Filling peer-vlan-vni map Info to internal DS
    app.appDB = dbs[db.ApplDB]
    err = app.getPeerVlanVniMapInfoFromDB(app.appDB, "", db.Key{})

    if err != nil {
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    ygot.BuildEmptyTree(vxlanObj.PeerVlanVniMaps)
    mapsInfo := vxlanObj.PeerVlanVniMaps.State
    ygot.BuildEmptyTree(mapsInfo)

    for mapName, _ := range app.peerVniTableMap {
        log.Info("mapName = ", mapName)
        ip, vlan := getPeerAddrVlanFromVxlanPeerKey(mapName)
        oneMapInfo, err := mapsInfo.NewPeerVlanVniMap(ip, vlan)
        if err != nil {
            log.Errorf("Creation of peer-vlan-vni map subtree for %s failed!", mapName)
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
        ygot.BuildEmptyTree(oneMapInfo)
        app.getVlanVniMapInfoFromInternalMap(mapName, true, oneMapInfo, nil)
    }
    payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))

    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp) getPeerVlanVniMapSpecificAttr(targetUriPath string, mapName string,
						ocPeerMapVal *ocbinds.OpenconfigVxlanCls_Vxlan_PeerVlanVniMaps_State_PeerVlanVniMap) (bool, error) {
	switch targetUriPath {
    case "/openconfig-vxlan-cls:vxlan/peer-vlan-vni-maps/state/peer-vlan-vni-map/vni-id":
		val, e := getVxlanAttr(app.peerVniTableMap, mapName, VNI_FIELD)
		if len(val) > 0 {
			vniVal, err := strconv.Atoi(val)
			vni := new(uint32)
			*vni = uint32(vniVal)
			if err == nil {
				ocPeerMapVal.VniId = vni
				return true, nil
			}
		}
		return true, e

	default:
        log.Infof(targetUriPath + " - Unsupported attribute")
    }
    return false, nil
}

func (app *VxlanApp)constructPeerVlanVniMapOCInfo(targetUriPath string,
						      vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                              dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
    var resp GetResponse
    pathInfo := app.path

    if vxlanObj.PeerVlanVniMaps == nil {
        err = tlerr.NotSupported("PeerVlanVniMaps container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    if vxlanObj.PeerVlanVniMaps.State == nil {
        err = tlerr.NotSupported("PeerVlanVniMaps state container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    // Get request for a specific peer-vlan-vni map
    if vxlanObj.PeerVlanVniMaps.State.PeerVlanVniMap != nil &&
          len(vxlanObj.PeerVlanVniMaps.State.PeerVlanVniMap) > 0 &&
          pathInfo.HasVar("peer-ip") == true && pathInfo.HasVar("vlan-id") == true {

        log.Info("Get a specific peer-vlan-vni map config request!")

        ip := pathInfo.Var("peer-ip")
        vlan := pathInfo.Var("vlan-id")
        log.Infof("Peer-ip = %s vlan-id = %s", ip, vlan)
        vlanInt, _ := strconv.Atoi(vlan)

        mapName := getVxlanPeerEntryKeyStrFromOCKey("Vlan"+vlan, ip)
        app.appDB = dbs[db.ApplDB]

        // Filling PeerVlanvni map Info to internal DS
        err = app.getPeerVlanVniMapInfoFromDB(app.appDB, mapName, asKey("Vlan"+vlan, ip))
        if err != nil {
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }

        // Check if the request is for a specific attribute in peer-vlan-vni-map container
        ocPeerMap := &ocbinds.OpenconfigVxlanCls_Vxlan_PeerVlanVniMaps_State_PeerVlanVniMap{}
        ok, e :=  app.getPeerVlanVniMapSpecificAttr(targetUriPath, mapName, ocPeerMap)
        if ok {
			if e != nil {
				return GetResponse{Payload: payload, ErrSrc: AppErr}, e
			}
			payload, err = dumpIetfJson(ocPeerMap)
			if err == nil {
				return GetResponse{Payload: payload}, err
			} else {
				return GetResponse{Payload: payload, ErrSrc: AppErr}, err
			}
        }

        ygot.BuildEmptyTree(vxlanObj.PeerVlanVniMaps)
        ygot.BuildEmptyTree(vxlanObj.PeerVlanVniMaps.State)
        mapOCKey := ocbinds.OpenconfigVxlanCls_Vxlan_PeerVlanVniMaps_State_PeerVlanVniMap_Key{PeerIp: ip, VlanId: uint16(vlanInt)}
        mapInfo := vxlanObj.PeerVlanVniMaps.State.PeerVlanVniMap[mapOCKey]
        ygot.BuildEmptyTree(mapInfo)

        app.getVlanVniMapInfoFromInternalMap(mapName, true, mapInfo, nil)

        // Dump the contents, if get request is valid
        if *app.ygotTarget == mapInfo {
            payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
        } else {
            log.Info("Not supported get type!")
            err = tlerr.NotSupported("Requested get-type not supported!")
        }
        resp = GetResponse{Payload: payload}
    } else {
        log.Info("Get all peer-vlan-vni-maps(without key) config request!")
        resp, err = app.constructPeerVlanVniMapsOCInfo(vxlanObj, dbs)
    }
    return resp, err
}

func (app *VxlanApp) getTunnelInfoFromDB(dbs [db.MaxDB]*db.DB, tunnelName string,
                                      tunnelKey db.Key) error {
    var err error
    app.configDB = dbs[db.ConfigDB]
    app.stateDB = dbs[db.StateDB]
    app.ApplDB = dbs[db.ApplDB]

    if len(tunnelName) > 0 {
        // Fetching DB data for a tunnel
        log.Infof("Updating tunnel:%s[key:%s] info from STATE-DB to Internal DS",
                    tunnelName, tunnelKey)
        tunnelInfo, err := app.stateDB.GetEntry(app.tunnelTs, tunnelKey)
        if err != nil {
            log.Errorf("Error found on fetching tunnel:%s info from STATE_DB", tunnelName)
            err = tlerr.NotFound("No such tunnel exists.")
            return err
        }
        if tunnelInfo.IsPopulated() {
            app.tunnelTableMap[tunnelName] = dbEntry{entry: tunnelInfo}
        } else {
            return errors.New("Populating tunnel info for " + tunnelName + "failed")
        }
    } else {
        log.Info("STATE-DB get for all tunnels")
        keys, _ := app.stateDB.GetKeys(app.tunnelTs)
        if len(keys) == 0 {
            // P2MP tunnels details are stored in APPL_DB and in CONFIG_DB
            vtep_keys, _ := app.configDB.GetKeys(app.intfVxlanTs)
            for _, vtep_key := range vtep_keys {
                var entry dbEntry
                var curr db.Value
                var src_ip string
                vtep_entry, _ := app.configDB.GetEntry(app.intfVxlanTs, vtep_key)
                if vtep_entry.IsPopulated() {
                    src_ip = vtep_entry.Get("src_ip")
                }
                tunnel_map_keys, _ := app.configDB.GetKeysPattern(app.intfVxlanMapTs, asKey(vtep_key.Get(0)+ CONFIG_DB_SEPARATOR + "*"))
                for _, key := range tunnel_map_keys {
                    // Get vlan name from VXLAN_TUNNEL_MAP|vtep1|map_20123_Vlan123
                    tmp_entry, _ := app.configDB.GetEntry(app.intfVxlanMapTs, key)
                    if tmp_entry.IsPopulated() {
                        vlan_name := tmp_entry.Get("vlan")
                        vlan_dst_ip_keys, _ := app.ApplDB.GetKeysPattern(app.peerVniAppTableTs, asKey(vlan_name+ APPL_DB_SEPARATOR + "*"))
                        prev_dst_ip := ""
                        // Extract the dst_ip data from APPL_DB table.  Eg.VXLAN_REMOTE_VNI_TABLE:Vlan123:10.41.0.41
                        for _, vlan_dst_ip_key := range vlan_dst_ip_keys {
                            if prev_dst_ip != vlan_dst_ip_key.Get(1) {
                                curr = db.Value{Field: make(map[string]string)}
                                curr.Field[SOURCE_IP_FIELD] = src_ip
                                curr.Field[DST_IP_FIELD] = vlan_dst_ip_key.Get(1)
                                // STATE_DB doesn't contain the tunnel status
                                // if the remote vtep data is present in APPL_DB consider it as oper_up
                                curr.Field[TUNNEL_STATUS_FIELD] = "up"
                                curr.Field[TUNNEL_SOURCE_FIELD] = EVPN_SRC
                                entry.entry = curr
                                app.tunnelTableMap[EVPN_SRC + "_" + vlan_dst_ip_key.Get(1)] = entry
                                prev_dst_ip = vlan_dst_ip_key.Get(1)
                            }
                        }
                    }
                }
            }
        } else {
            for _, key := range keys {
                app.getTunnelInfoFromDB(dbs, key.Get(0), key)
            }
        }
    }
    return err
}

func (app *VxlanApp) getTunnelInfoFromInternalMap(tunnelName string,
                        tunnelInfo *ocbinds.OpenconfigVxlanCls_Vxlan_Tunnels_State_Tunnel) {

    // Handling vxlan tunnel attributes
	if entry, ok := app.tunnelTableMap[tunnelName]; ok {
		tunnelData := entry.entry

        name := new(string)
        *name = tunnelName
        tunnelInfo.Name = name

		for tunnelAttr := range tunnelData.Field {
			switch tunnelAttr {
			case DST_IP_FIELD:
				dstIp := tunnelData.Get(tunnelAttr)
				peerIp :=  new(string)
				*peerIp = dstIp
				tunnelInfo.PeerIp = peerIp
				log.Infof("tunnelInfo.PeerIp=%s",*peerIp)

			case SOURCE_IP_FIELD:
				ip := tunnelData.Get(tunnelAttr)
				srcIp :=  new(string)
				*srcIp = ip
				tunnelInfo.SourceIp = srcIp
				log.Infof("tunnelInfo.SourceIp=%s",*srcIp)

            case VTEP_MAC:
				mac := tunnelData.Get(tunnelAttr)
				vtepMac :=  new(string)
				*vtepMac = mac
				tunnelInfo.VtepMac = vtepMac
				log.Infof("tunnelInfo.vtepMac=%s",*vtepMac)

			case TUNNEL_STATUS_FIELD:
				status := tunnelData.Get(tunnelAttr)
				var statusEnum ocbinds.E_OpenconfigVxlanCls_TunnelStatus
				statusEnum = getOCTunnelStatusFromSonicTunnelStatus(status)
				tunnelInfo.Status = statusEnum
				log.Info("tunnelInfo.Status = ", statusEnum)

			case TUNNEL_SOURCE_FIELD:
				src := tunnelData.Get(tunnelAttr)
				var srcEnum ocbinds.E_OpenconfigVxlanCls_TunnelType
				srcEnum = getOCTunnelSrcFromSonicTunnelSrc(src)
				tunnelInfo.Type = srcEnum
				log.Info("tunnelInfo.Type= ", srcEnum)

			default:
                log.Info("Not a valid attribute!")
			}
		}
	}
}

func (app *VxlanApp)constructTunnelsOCInfo(vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                                               dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
    isVM := is_Platform_VM()

    // Filling tunnel Info to internal DS
    if isVM == false {
        err = app.getTunnelInfoFromDB(dbs, "", db.Key{})

        if err != nil {
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
    }

    ygot.BuildEmptyTree(vxlanObj.Tunnels)
    tunnelsInfo := vxlanObj.Tunnels.State
    ygot.BuildEmptyTree(tunnelsInfo)

    for tunnelName, _ := range app.tunnelTableMap {
        log.Info("tunnelName = ", tunnelName)
        ip := getDstIpFromTunnelMapKey(tunnelName)
		log.Infof("tunnelIp = %s", ip)
        tunnelInfo, err := tunnelsInfo.NewTunnel(tunnelName)
        if err != nil {
            log.Errorf("Creation of tunnel subtree for %s failed!", tunnelName)
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
        ygot.BuildEmptyTree(tunnelInfo)
        app.getTunnelInfoFromInternalMap(tunnelName, tunnelInfo)
    }
    payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))

    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp) getTunnelInfoSpecificAttr(targetUriPath string, tunName string,
						ocStVal *ocbinds.OpenconfigVxlanCls_Vxlan_Tunnels_State_Tunnel) (bool, error) {
    switch targetUriPath {
    case "/openconfig-vxlan-cls:vxlan/tunnels/state/tunnel/source-ip":
		val, e := getVxlanAttr(app.tunnelTableMap, tunName, SOURCE_IP_FIELD)
        if len(val) > 0 {
            ip := new(string)
            *ip = val
            ocStVal.SourceIp = ip
            log.Info("ocStVal.SourceIp=", val)
            return true, nil
        }
		return true, e

    case "/openconfig-vxlan-cls:vxlan/tunnels/state/tunnel/peer-ip":
        val, e := getVxlanAttr(app.tunnelTableMap, tunName, DST_IP_FIELD)
        if len(val) > 0 {
            ip := new(string)
            *ip = val
            ocStVal.PeerIp = ip
            log.Info("ocStVal.PeerIp=", val)
            return true, nil
        }
        return true, e

	case "/openconfig-vxlan-cls:vxlan/tunnels/state/tunnel/status":
		val, e := getVxlanAttr(app.tunnelTableMap, tunName, TUNNEL_STATUS_FIELD)
        if len(val) > 0 {
            ocStVal.Status = getOCTunnelStatusFromSonicTunnelStatus(val)
            log.Info("ocStVal.Status=", val)
            return true, nil
        }
		return true, e

	case "/openconfig-vxlan-cls:vxlan/tunnels/state/tunnel/type":
		val, e := getVxlanAttr(app.tunnelTableMap, tunName, TUNNEL_SOURCE_FIELD)
        if len(val) > 0 {
            ocStVal.Type = getOCTunnelSrcFromSonicTunnelSrc(val)
            log.Info("ocStVal.Type=", val)
            return true, nil
        }
		return true, e

    default:
        log.Infof(targetUriPath + " - Unsupported attribute")
    }
    return false, nil
}

func (app *VxlanApp)constructTunnelOCInfo(targetUriPath string,
                        vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                        dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
    var resp GetResponse
    pathInfo := app.path

    isVM := is_Platform_VM()

    if vxlanObj.Tunnels == nil {
        err = tlerr.NotSupported("Tunnels container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    if vxlanObj.Tunnels.State == nil {
        err = tlerr.NotSupported("Tunnels state container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    // Get request for a vxlan tunnel
    if vxlanObj.Tunnels.State.Tunnel != nil && len(vxlanObj.Tunnels.State.Tunnel) > 0 &&
                pathInfo.HasVar("name") == true {
        log.Info("Get a specific vxlan tunnel request!")

        tunnelName := pathInfo.Var("name")
        log.Infof("Name = %s ", tunnelName)

        app.appDB = dbs[db.StateDB]

        // Filling tunnel Info to internal DS
        if isVM == false {
            err = app.getTunnelInfoFromDB(dbs, tunnelName, asKey(tunnelName))
            if err != nil {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, err
            }
        }
		// Check if the request is for a specific attribute in tunnel state container
        ocTun := &ocbinds.OpenconfigVxlanCls_Vxlan_Tunnels_State_Tunnel{}
        ok, e :=  app.getTunnelInfoSpecificAttr(targetUriPath, tunnelName, ocTun)
        if ok {
            if e != nil {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, e
            }
            payload, err = dumpIetfJson(ocTun)
            if err == nil {
                return GetResponse{Payload: payload}, err
            } else {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, err
            }
        }

        ygot.BuildEmptyTree(vxlanObj.Tunnels.State)
        tunnelInfo := vxlanObj.Tunnels.State.Tunnel[tunnelName]
        ygot.BuildEmptyTree(tunnelInfo)

        app.getTunnelInfoFromInternalMap(tunnelName, tunnelInfo)

        // Dump the contents, if get request is valid
        if *app.ygotTarget == tunnelInfo {
            payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
        } else {
            log.Info("Not supported get type!")
            err = tlerr.NotSupported("Requested get-type not supported!")
        }
        resp = GetResponse{Payload: payload}
    } else {
        log.Info("Get all tunnels(without key) request!")
        resp, err = app.constructTunnelsOCInfo(vxlanObj, dbs)
    }
    return resp, err
}

func (app *VxlanApp) handleVxlanProfileConfigDelete(d *db.DB) ([]db.WatchKeys, error) {
    var err error
    var keys []db.WatchKeys

    nodeInfo, err := getTargetNodeYangSchema(app.path.Path,
                                      (*app.ygotRoot).(*ocbinds.Device))
    if err != nil {
        log.Error("Failed to get target node")
        return keys, tlerr.InvalidArgs("Failed to get target node.")
    }

    // Fetch the localhost entry from config DB
    var entry dbEntry
    entry.key = asKey(DEVICE_METADATA_ENTRY)
    curr, err := d.GetEntry(app.profileTs, entry.key)

    // Throw error if entry not exists
    if err != nil {
        return keys, tlerr.NotFound("Localhost vxlan-profile entry doesn't exist.")
    }

    if nodeInfo.IsLeaf() {
        switch nodeInfo.Name {
            case "profile":
                curr.Field[VXLAN_PROFILE] = "disable"
                entry.op = UPDATE
                entry.entry = curr
            default:
                log.Errorf("Removing %s is not supported = ", nodeInfo.Name)
                return keys, tlerr.NotSupported("Removing '%s' is not supported.",
                                nodeInfo.Name)
        }
    } else {
        log.Error("This yang type is not handled currently")
        return keys, tlerr.NotSupported("Yang type not supported")
    }

    entry.ts = app.profileTs
    log.Infof("Translated DB entry [op:%d][table:%s][key:%s]",
              entry.op, entry.ts.Name, entry.key)
    app.profileTableMap[DEVICE_METADATA_ENTRY] = entry

    return keys, err
}

func (app *VxlanApp) getVxlanProfileInfoFromInternalMap(ocCfgVal *ocbinds.OpenconfigVxlanCls_Vxlan_Config) {
    status, _ := getVxlanAttr(app.profileTableMap, DEVICE_METADATA_ENTRY, VXLAN_PROFILE)
    var flag bool
    if len(status) > 0 {
        if (status == "enable") {
            flag = true
        } else {
            flag = false
        }
    } else {
        flag = true
    }
    ocCfgVal.Profile = &flag
}


func (app *VxlanApp) getVxlanConfigSpecificAttr(targetUriPath string,
                            ocCfgVal *ocbinds.OpenconfigVxlanCls_Vxlan_Config) (bool, error) {
    switch targetUriPath {
    case "/openconfig-vxlan-cls:vxlan/config/profile":
		app.getVxlanProfileInfoFromInternalMap(ocCfgVal)
		return true, nil
	default:
        log.Infof(targetUriPath + " - Unsupported attribute")
    }
    return false, nil
}


func (app *VxlanApp)constructVxlanCfgOCInfo(targetUriPath string,
                           vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan, dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte

    // Filling Vxlan profile Info to internal DS
    app.appDB = dbs[db.ConfigDB]
    metaDataInfo, err := (app.appDB).GetEntry(app.profileTs, asKey(DEVICE_METADATA_ENTRY))
    if err != nil {
        log.Error("Error found on fetching localhost info from CFG-DB")
        err = tlerr.NotFound("No such meta_data|localhost entry exists.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }
    if metaDataInfo.IsPopulated() {
        app.profileTableMap[DEVICE_METADATA_ENTRY] = dbEntry{entry: metaDataInfo}
    } else {
        err = errors.New("Populating vxlan profile info for " + DEVICE_METADATA_ENTRY + "failed")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    // Check if the request is for a specific attribute in vxlan config container
    ocCfg := &ocbinds.OpenconfigVxlanCls_Vxlan_Config{}
    ok, e :=  app.getVxlanConfigSpecificAttr(targetUriPath, ocCfg)
    if ok {
        if e != nil {
            return GetResponse{Payload: payload, ErrSrc: AppErr}, e
        }
        payload, err = dumpIetfJson(ocCfg)
        if err == nil {
            return GetResponse{Payload: payload}, err
        } else {
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
    }

    vxlanCfg := vxlanObj.Config
    ygot.BuildEmptyTree(vxlanCfg)
    app.getVxlanProfileInfoFromInternalMap(vxlanCfg)

    // Check if the request is for vxlan config container
    payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
    if err != nil {
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }
    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp) translateOCVxlanConfigToDB(d *db.DB, op int,
                       oc_val *ocbinds.OpenconfigVxlanCls_Vxlan) ([]db.WatchKeys, error) {
    var err error = nil
    var keys []db.WatchKeys
    var entry dbEntry
    var updateDB bool

    updateDB = false
    entry.op = op
    entry.ts = app.profileTs

    //Key generation
    entry.key = asKey(DEVICE_METADATA_ENTRY)
    // Fetch the localhost entry from DB
    curr, err := d.GetEntry(entry.ts, entry.key)

    if op == CREATE {
	    // Throw error if global config entry exists for CREATE operation
        if curr.IsPopulated() {
            log.Error("Devicemeta|Localhost entry exists already")
            return keys, tlerr.AlreadyExists("Devicemeta|Localhost entry exists already.")
        } else {
            curr = db.Value{Field: make(map[string]string)}
        }
    }

    // For UPDATE operation, create the entry if does not exist
    if err != nil && op == UPDATE {
        log.Infof("Devicemeta|Localhost entry not found, creating it")
        entry.op = CREATE
        curr = db.Value{Field: make(map[string]string)}
        curr.Field[VXLAN_PROFILE] = "disable"
        err = nil
    }

    if oc_val.Config != nil {
        if oc_val.Config.Profile != nil {
            log.Info("VxlanProfile Enabled = ", *oc_val.Config.Profile)
            if *oc_val.Config.Profile  {
                curr.Field[VXLAN_PROFILE] = "enable"
            } else {
                curr.Field[VXLAN_PROFILE] = "disable"
            }
        }
        updateDB = true
    }
    log.Infof("Translated DB entry [op:%d][table:%s][key:%s] updateDB:%t",
              entry.op, entry.ts.Name, entry.key, updateDB)
    entry.entry = curr

    if updateDB == true {
        app.profileTableMap[DEVICE_METADATA_ENTRY] = entry
    }
    return keys, err
}

func (app *IntfApp) translateOCVxlanIntfSipConfigToDB(d *db.DB, op int,
                       sip string, vtep_mac string,ifName string) ([]db.WatchKeys, error) {
    var err error = nil
    var keys []db.WatchKeys
    var entry dbEntry

    entry.op = op
    entry.ts = app.intfVxlanTs
    entry.key = asKey(ifName)

    curr, err := getIntfFromDb(d, ifName)

    if err != nil {
        log.Info("Vxlan if entry not found, error returned")
        return keys, err
    }

    curr.Field[SOURCE_IP_FIELD] = sip
    curr.Field[VTEP_MAC] = vtep_mac

    log.Infof("Translated DB entry [op:%d][table:%s][key:%s] ",
              entry.op, entry.ts.Name, entry.key)
    entry.entry = curr
    app.ifVxlanMap[ifName] = entry

    return keys, err
}

func (app *IntfApp) handleVxlanNvoConfigToDB(d *db.DB, op int,
                                      ifName string) ([]db.WatchKeys, error) {
    var err error = nil
    var keys []db.WatchKeys
    var entry dbEntry
    var updateDB bool

    updateDB = false
    entry.op = op
    entry.ts = app.intfVxlanNvoTs
    entry.key = asKey(NVO_ENTRY_KEY)

    // Fetch the VXLAN_EVPN_NVO entry from DB
    curr, err := d.GetEntry(entry.ts, entry.key)

    if err != nil && op == DELETE {
        return keys, tlerr.NotFound("nvo1 entry doesn't exist.")
    }

    if op == CREATE {
        // Throw error if the entry exists for CREATE operation
        if curr.IsPopulated() {
            log.Error("nvo1 entry exists already")
            return keys, tlerr.AlreadyExists("nvo1 entry exists already.")
        } else {
            curr = db.Value{Field: make(map[string]string)}
        }
    }

    // For UPDATE operation, create the entry if does not exist
    if err != nil && op == UPDATE {
        log.Infof("nvo1 entry not found, creating it")
        entry.op = CREATE
        curr = db.Value{Field: make(map[string]string)}
        curr.Field[SOURCE_VTEP_FIELD] = ifName
        err = nil
    }
    updateDB = true

    log.Infof("Translated DB entry [op:%d][table:%s][key:%s] updateDB:%t",
              entry.op, entry.ts.Name, entry.key, updateDB)
    entry.entry = curr

    if updateDB == true {
        app.ifVxlanNvoMap[NVO_ENTRY_KEY] = entry
    }
    return keys, err
}

func (app *IntfApp) translateOCVxlanSipConfigToDB(d *db.DB, op int,
                    vxlanCfg *ocbinds.OpenconfigInterfaces_Interfaces_Interface_VxlanIf_Config, ifName string) ([]db.WatchKeys, error) {
    var err error = nil
    var keys []db.WatchKeys

    if vxlanCfg.SourceVtepIp != nil {
        sip := *vxlanCfg.SourceVtepIp
		//Check if the source-vtep ip is same as the Loopback0 interface's IP
	    log.Info("srcVtepIp = ", sip)
        isExist, _ := isSameIpAlreadyConfiguredOnLoIntf(d, sip)
        if !isExist {
            log.Errorf("Source vtep ip %s is not configured on any loopback interface", sip)
            errStr := "Source vtep ip " + sip + " is not configured on any loopback interface"
            return keys, tlerr.InternalError{Format: errStr}
        }

        vtep_mac := *vxlanCfg.VtepMac

        //Update SIP field in VXLAN_TUNNEL table. 
        keys, err = app.translateOCVxlanIntfSipConfigToDB(d, op, sip, vtep_mac, ifName)
        if err != nil {
            return keys, err
        }

		//Create "VXLAN_EVPN_NVO|nvo1" default entry after
        //adding SIP into VXLAN_TUNNEL table.
        keys, err = app.handleVxlanNvoConfigToDB(d, op, ifName)
        if err != nil {
            return keys, err
        }
	}
	return keys, err
}

func (app *IntfApp) isVxlanSipConfigured(d *db.DB, ifName string) (bool) {

    vxlanIfInfo, err := d.GetEntry(app.intfVxlanTs, asKey(ifName))
    if err != nil {
        log.Errorf("Error found on fetching Vxlan intf :%s info ", ifName)
        return false
    }
    if vxlanIfInfo.IsPopulated() {
        if val, ok := vxlanIfInfo.Field[SOURCE_IP_FIELD]; ok && len(val) > 0 {
            return true
        }
    }

	return false
}

func getVxlanMapEntryKeyStrFromOCKey(vni string, vlan string) (string) {
    //append 'map' at the begining of the key string
    return "map" + "_" + vni + "_Vlan" + vlan
}

func getDstIpFromTunnelMapKey(key string) (string) {
	return strings.Trim(key, "EVPN_")
}

func (app *IntfApp) translateOCVxlanMapConfigToDB(d *db.DB, op int,
                   vxlanMap *ocbinds.OpenconfigInterfaces_Interfaces_Interface_VxlanIf_Config_VniInstances_VniInstance,
                   ifName string) ([]db.WatchKeys, error) {
    var err error = nil
    var keys []db.WatchKeys
    var vlanid uint16
    var vnid uint32
    var count uint16
    var it uint16

    if !(app.isVxlanSipConfigured(d, ifName)) {
        log.Error("Vxlan tunnel map entry cannot be configured, since SIP doesnt exist for this tunnel")
        errStr := "Vxlan map entry is not allowed, since source-ip is not present"
        return keys, tlerr.InternalError{Format: errStr}
    }

    if vxlanMap.VniId != nil {
        vnid = *vxlanMap.VniId
    }
    if vxlanMap.VlanId != nil {
        vlanid = *vxlanMap.VlanId
    }
    if vxlanMap.MapCount != nil {
        count = *vxlanMap.MapCount
    }
    // Check map-count holds valid vlan-id
    keys, err = validateVlanMapConfig(d, int(vlanid), int(count))
    if err != nil {
        return keys, err
    }

    for it = 0 ; it < count; it++ {
        var entry dbEntry
        entry.op = op
        entry.ts = app.intfVxlanMapTs
        vlanStr := strconv.FormatUint(uint64(vlanid+it),10)
        vniStr := strconv.FormatUint(uint64(vnid+uint32(it)), 10)

        keyStr := getVxlanMapEntryKeyStrFromOCKey(vniStr, vlanStr)
        entry.key = asKey(ifName, keyStr)

        curr, err := d.GetEntry(app.intfVxlanMapTs, entry.key)
        if op == CREATE {
            // Throw error if map entry exists for CREATE operation
            if curr.IsPopulated() {
                log.Error("Vxlan Map entry ", entry.key, " exists already")
                return keys, tlerr.AlreadyExists("Vxlan Map entry exists already.", entry.key)
            } else {
                curr = db.Value{Field: make(map[string]string)}
            }
        }
        // For UPDATE operation, create the entry if does not exist
        if err != nil && op == UPDATE {
            entry.op = CREATE
            log.Infof("Vxlan Map entry %s entry not found, creating one", keyStr)
            curr = db.Value{Field: make(map[string]string)}
            err = nil
        }
        curr.Field[VLAN_FIELD] = "Vlan"+vlanStr
        curr.Field[VNI_FIELD] = vniStr

        l2_vxlan_support, err := checkL2VxLANSupport(d)
        if(err != nil){
            return keys,err
        }
        if !l2_vxlan_support {
            curr.Field[KERNEL_ONLY_CONFIG_FIELD] = "true"
        }

        log.Infof("Translated VxlanMap DB entry [op:%d][table:%s][key:%s]",
                    entry.op, entry.ts.Name, entry.key)
        entry.entry = curr
        app.ifVxlanVlanVniMap[keyStr] = entry
    }
    return keys, err
}

func (app *IntfApp) translateOCVxlanIntfConfigToDB(d *db.DB, op int,
                        intf *ocbinds.OpenconfigInterfaces_Interfaces_Interface)([]db.WatchKeys, error) {
    var err error
    var keys []db.WatchKeys
    pathInfo :=  app.path
    log.Infof("Received for path %s; vars=%v; op=%d",  pathInfo.Template, pathInfo.Vars, op)

    if intf.VxlanIf != nil && intf.VxlanIf.Config != nil {
        ifName := *intf.Name
        if intf.VxlanIf.Config.SourceVtepIp != nil {
            keys, err = app.translateOCVxlanSipConfigToDB(d, op, intf.VxlanIf.Config, ifName)

        } else if intf.VxlanIf.Config.VniInstances != nil && intf.VxlanIf.Config.VniInstances.VniInstance != nil &&
                            len(intf.VxlanIf.Config.VniInstances.VniInstance) > 0 {
            for vxlanMapOCKey, _ := range intf.VxlanIf.Config.VniInstances.VniInstance {
                log.Info("vxlanMapOCKey = ", vxlanMapOCKey)
                log.Infof("Vni-id = %s, vlan-id = %s, map-count = %s ifName = %s",
                            pathInfo.Var("vni-id"), pathInfo.Var("vlan-id"), pathInfo.Var("map-count"), ifName)
                keys, err = app.translateOCVxlanMapConfigToDB(d, op,
                                         intf.VxlanIf.Config.VniInstances.VniInstance[vxlanMapOCKey], ifName)
                if err != nil {
                    return keys, err
                }
            }
        }
    }

    return keys, err
}

func (app *VxlanApp) getPeerVtepMacSpecificAttr(targetUriPath string, mac string,
                                   ocMacVal *ocbinds.OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac)(bool, error) {
    switch targetUriPath {
	case "/openconfig-vxlan-cls:vxlan/peer-macs/state/peer-mac/peer-ip":
        val, e := getVxlanAttr(app.peerMacTableMap, mac, REMOTE_VTEP_FIELD)
        if len(val) > 0 {
            ip := new(string)
            *ip = val
            ocMacVal.PeerIp = ip
            log.Info("ocMacVal.PeerIp=", val)
            return true, nil
        }
        return true, e

    case "/openconfig-vxlan-cls:vxlan/peer-macs/state/peer-mac/vni-id":
        val, e := getVxlanAttr(app.peerMacTableMap, mac, VNI_FIELD)
        if len(val) > 0 {
            vniVal, err := strconv.Atoi(val)
            vni := new(uint32)
            *vni = uint32(vniVal)
            if err == nil {
                ocMacVal.VniId = vni
                return true, nil
            }
        }
        return true, e

    case "/openconfig-vxlan-cls:vxlan/peer-macs/state/peer-mac/type":
		val, e := getVxlanAttr(app.peerMacTableMap, mac, MAC_TYPE)
        if len(val) > 0 {
			ocMacVal.Type = getOCPeerVtepMacTypeFromSonicVtepMacType(val)
            log.Info("ocMacVal.Type=", val)
            return true, nil
        }
        return true, e

    default:
        log.Infof(targetUriPath + " - Unsupported attribute")
    }
    return false, nil
}

func (app *VxlanApp) getPeerVtepMacInfoFromInternalMap(macVlan string,
                        macInfo *ocbinds.OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac) {
    var entry dbEntry
    var ok bool

    entry, ok = app.peerMacTableMap[macVlan]

    // Handling the vlan vni map attributes
    if ok {
        macData := entry.entry
        log.Info("MacVlan name= ", macVlan)

        mac := new(string)
		vlanId := new(uint16)
        *mac, *vlanId = getPeerAddrVlanFromVxlanPeerKey(macVlan)
		macInfo.MacAddress = mac
        macInfo.VlanId = vlanId
		log.Infof("macInfo.VlanId=%d, MacAddress=%s", *vlanId, *mac)

        for macVlanAttr := range macData.Field {
            switch macVlanAttr {
            case VNI_FIELD:
                vniStr := macData.Get(macVlanAttr)
                vni, err := strconv.Atoi(vniStr)
                vniId := new(uint32)
                *vniId = uint32(vni)
                if err == nil {
                    macInfo.VniId = vniId
                    log.Infof("macInfo.VniId=%d", *vniId)
                }

            case REMOTE_VTEP_FIELD:
                ip := new(string)
                *ip = macData.Get(macVlanAttr)
                macInfo.PeerIp = ip
                log.Infof("macInfo.PeerIp=%s", *ip)

            case MAC_TYPE:
                macType := macData.Get(macVlanAttr)
                var macTypeEnum ocbinds.E_OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac_Type
                macTypeEnum = getOCPeerVtepMacTypeFromSonicVtepMacType(macType)
                macInfo.Type = macTypeEnum
                log.Info("macInfo.Type = ", macType)

            default:
                log.Info("Not a valid attribute=",macVlanAttr)
            }
        }
    }
}


func (app *VxlanApp) getPeerMacInfoFromDB(d *db.DB, peerMac string, peerMacKey db.Key) error {
    var err error

    if len(peerMac) > 0 {
        // Fetching DB data for a specific vtep learned macs
        log.Infof("Updating peerMac:%s from APPL_DB to Internal DS", peerMac)
        peerMacInfo, err := d.GetEntry(app.peerMacAppTableTs, peerMacKey)
        if err != nil {
            log.Errorf("Error found on fetching peer-mac:%s info from APPL_DB", peerMac)
            err = tlerr.NotFound("No such peer mac exists.")
            return err
        }
        if peerMacInfo.IsPopulated() {
            app.peerMacTableMap[peerMac] = dbEntry{entry: peerMacInfo}
        } else {
            return errors.New("Populating peer-mac info for " + peerMac + "failed")
        }
    } else {
        log.Info("DB get for all vteps remotely learned macs")
        keys, _ := d.GetRawKeys(app.peerMacAppTableTs)
        for _, key := range keys {
            log.Infof("Get RTEP State FDB with key: %v type: %T", key, key)
            fdbKey := strings.SplitN(key, ":", 2)
            macKey := strings.SplitN(fdbKey[1], ":", 2)
            log.Info("macKey: ", macKey)
            peerMac := getVxlanPeerEntryKeyStrFromOCKey(macKey[0], macKey[1])
            app.getPeerMacInfoFromDB(d, peerMac, asKey(macKey[0],macKey[1]))
        }
    }
    return err
}

func (app *VxlanApp)constructPeerMacsOCInfo(vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                                               dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
    isVM := is_Platform_VM()

    // Filling all peer vteps' mac Info to internal DS
    app.appDB = dbs[db.ApplDB]
    if isVM == false {
        err = app.getPeerMacInfoFromDB(app.appDB, "", db.Key{})

        if err != nil {
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
    }

    ygot.BuildEmptyTree(vxlanObj.PeerMacs)
    vtepsMacInfo := vxlanObj.PeerMacs.State
    ygot.BuildEmptyTree(vtepsMacInfo)

    for macVlanName, _ := range app.peerMacTableMap {
        log.Info("macVlanName = ", macVlanName)
        mac, vlan := getPeerAddrVlanFromVxlanPeerKey(macVlanName)
        oneMacInfo, err := vtepsMacInfo.NewPeerMac(mac, vlan)
        if err != nil {
            log.Errorf("Creation of a specific mac entry subtree for %s failed!",
                                                         macVlanName)
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
        ygot.BuildEmptyTree(oneMacInfo)
        app.getPeerVtepMacInfoFromInternalMap(macVlanName, oneMacInfo)
    }
    payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))

    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp)constructPeerMacOCInfo(targetUriPath string,
                                   vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                                   dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
    var resp GetResponse
    pathInfo := app.path
    isVM := is_Platform_VM()

    if vxlanObj.PeerMacs == nil {
        err = tlerr.NotSupported("PeerMacs container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    if vxlanObj.PeerMacs.State == nil {
        err = tlerr.NotSupported("PeerMacs state container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    // Get request for a specific vtep remotely learned mac
    if vxlanObj.PeerMacs.State.PeerMac != nil && len(vxlanObj.PeerMacs.State.PeerMac) > 0 &&
                pathInfo.HasVar("mac-address") == true &&
				pathInfo.HasVar("vlan-id") == true {
        log.Info("Get a specific vtep learned peer-macs request!")

        vlan := pathInfo.Var("vlan-id")
		mac := pathInfo.Var("mac-address")
        log.Infof("Vlan-id = %s mac-address = %s", vlan, mac)
        vlanInt, _ := strconv.Atoi(vlan)

        peerMac := getVxlanPeerEntryKeyStrFromOCKey("Vlan"+vlan, mac)
        app.appDB = dbs[db.ApplDB]

        if isVM == false {
            // Filling remote vtep learned mac Info to internal DS
            err = app.getPeerMacInfoFromDB(app.appDB, peerMac, asKey("Vlan"+vlan, mac))
            if err != nil {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, err
            }
        }

        // Check if the request is for a specific attribute in a specific vtep learned mac state container
        ocPeerMac := &ocbinds.OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac{}
        ok, e :=  app.getPeerVtepMacSpecificAttr(targetUriPath, peerMac, ocPeerMac)
        if ok {
            if e != nil {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, e
            }
            payload, err = dumpIetfJson(ocPeerMac)
            if err == nil {
                return GetResponse{Payload: payload}, err
            } else {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, err
            }
        }

        ygot.BuildEmptyTree(vxlanObj.PeerMacs)
        ygot.BuildEmptyTree(vxlanObj.PeerMacs.State)
        macOCKey := ocbinds.OpenconfigVxlanCls_Vxlan_PeerMacs_State_PeerMac_Key{MacAddress: mac, VlanId: uint16(vlanInt)}
        peerMacInfo := vxlanObj.PeerMacs.State.PeerMac[macOCKey]
        ygot.BuildEmptyTree(peerMacInfo)

        app.getPeerVtepMacInfoFromInternalMap(peerMac, peerMacInfo)

        // Dump the contents, if get request is valid
        if *app.ygotTarget == peerMacInfo {
            payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
        } else {
            log.Info("Not supported get type!")
            err = tlerr.NotSupported("Requested get-type not supported!")
        }
        resp = GetResponse{Payload: payload}
    } else {
        log.Info("Get all vteps mac info(without key) request!")
        resp, err = app.constructPeerMacsOCInfo(vxlanObj, dbs)
    }
    return resp, err
}

func (app *VxlanApp) processActionClearTunnelCounters(dbs [db.MaxDB]*db.DB) (ActionResponse,error){
    var err error
    var resp ActionResponse
    app.countersDB = dbs[db.CountersDB]

    err = CopyDbTable(app.countersDB, COUNTERS_TABLE, CLEAR_COUNTERS_TABLE)
    if err == nil{
        var actionOutput struct {
            Output struct {
                Status int `json:"status"`
                StatusDetail string `json:"status-detail"`
            }`json:"openconfig-if-cls-ext:output"`
        }
        actionOutput.Output.Status = 0
        actionOutput.Output.StatusDetail = "Success"
        payload, _ := json.Marshal(&actionOutput)
        return ActionResponse{Payload: payload}, err
    }

    return resp,err
}

func (app *VxlanApp) getVxlanCounters(tunName string, attr string,
                                                 counter_val **uint64) error {
    val, e := getVxlanAttr(app.tunnelStatMap, tunName, attr)
    if len(val) > 0 {
        v, e := strconv.ParseUint(val, 10, 64)
        if e == nil {
            *counter_val = &v
            return nil
        }
    }
    return e
}

func (app *VxlanApp) getTunnelCounterInfoSpecificAttr(targetUriPath string, tunName string,
                        ctrVal *ocbinds.OpenconfigVxlanCls_Vxlan_Counters_Counter) (bool, error) {
    var e error
    var val string

    switch targetUriPath {
    case "/openconfig-vxlan-cls:vxlan/counters/counter/in-octets":
	    e = app.getVxlanCounters(tunName, "SAI_TUNNEL_STAT_IN_OCTETS", &ctrVal.InOctets)
		return true, e

	case "/openconfig-vxlan-cls:vxlan/counters/counter/in-pkts":
		e = app.getVxlanCounters(tunName, "SAI_TUNNEL_STAT_IN_PACKETS", &ctrVal.InPkts)
		return true, e

    case "/openconfig-vxlan-cls:vxlan/counters/counter/in-bps":
        val, e = getVxlanAttr(app.tunnelRateMap, tunName, "RX_BPS")
        if len(val) > 0 {
            bps := new(string)
            *bps = val
            ctrVal.InBps = bps
        }
        return true, e

    case "/openconfig-vxlan-cls:vxlan/counters/counter/in-pps":
        val, e = getVxlanAttr(app.tunnelRateMap, tunName, "RX_PPS")
        if len(val) > 0 {
            pps := new(string)
            *pps = val
            ctrVal.InPps = pps
        }
        return true, e

	case "/openconfig-vxlan-cls:vxlan/counters/counter/out-octets":
	    e = app.getVxlanCounters(tunName, "SAI_TUNNEL_STAT_OUT_OCTETS", &ctrVal.OutOctets)
		return true, e

	case "/openconfig-vxlan-cls:vxlan/counters/counter/out-pkts":
	    e = app.getVxlanCounters(tunName, "SAI_TUNNEL_STAT_OUT_PACKETS", &ctrVal.OutPkts)
		return true, e

    case "/openconfig-vxlan-cls:vxlan/counters/counter/out-bps":
        val, e = getVxlanAttr(app.tunnelRateMap, tunName, "TX_BPS")
        if len(val) > 0 {
            bps := new(string)
            *bps = val
            ctrVal.OutBps = bps
        }
        return true, e

    case "/openconfig-vxlan-cls:vxlan/counters/counter/out-pps":
        val, e = getVxlanAttr(app.tunnelRateMap, tunName, "TX_PPS")
        if len(val) > 0 {
            pps := new(string)
            *pps = val
            ctrVal.OutPps = pps
        }
        return true, e

    default:
        log.Infof(targetUriPath + " - Not a tunnel counter attribute")
    }
    return false, nil
}

func (app *VxlanApp) getTunCtrPollIntervalFromInternalMap(ctrInfo *ocbinds.OpenconfigVxlanCls_Vxlan_Counters) {
    //If there is no flex_counter_table|tunnel entry, return
    if len(app.tunnelFlexCtrMap) == 0 {
        return
    }
    status, _ := getVxlanAttr(app.tunnelFlexCtrMap, FLEX_CTR_TUN_ENTRY, TUN_CTR_STATUS)
    if len(status) > 0  {
        interval, _ := getVxlanAttr(app.tunnelFlexCtrMap, FLEX_CTR_TUN_ENTRY, RATE_INTERVAL)
        pollInt := new(uint16)
        if len(interval) > 0 {
            pollIntVal, _ := strconv.Atoi(interval)
            *pollInt = uint16(pollIntVal/MS_IN_SECONDS)
        } else {
            //If there is no poll_interval field, fill the default value
            *pollInt = DEFAULT_RATE_INTERVAL
        }
        ctrInfo.RateInterval = pollInt
    }
}

func (app *VxlanApp) getTunnelCounterInfoFromInternalMap(tunName string,
                              ctrInfo *ocbinds.OpenconfigVxlanCls_Vxlan_Counters_Counter) {
    if len(app.tunnelStatMap) == 0 {
        log.Errorf("Tunnel stat info not present for interface : %s", tunName)
        return
    }
    if tunStatInfo, ok := app.tunnelStatMap[tunName]; ok {
        inOctet := new(uint64)
        inOctetVal, _ := strconv.Atoi(tunStatInfo.entry.Field["SAI_TUNNEL_STAT_IN_OCTETS"])
        *inOctet = uint64(inOctetVal)
        ctrInfo.InOctets = inOctet

		inPkt := new(uint64)
		inPktVal, _ := strconv.Atoi(tunStatInfo.entry.Field["SAI_TUNNEL_STAT_IN_PACKETS"])
        *inPkt = uint64(inPktVal)
        ctrInfo.InPkts = inPkt

		outOctet := new(uint64)
        outOctetVal, _ := strconv.Atoi(tunStatInfo.entry.Field["SAI_TUNNEL_STAT_OUT_OCTETS"])
        *outOctet = uint64(outOctetVal)
        ctrInfo.OutOctets = outOctet

		outPkt := new(uint64)
		outPktVal, _ := strconv.Atoi(tunStatInfo.entry.Field["SAI_TUNNEL_STAT_OUT_PACKETS"])
        *outPkt = uint64(outPktVal)
        ctrInfo.OutPkts = outPkt
    }

    if tunRateInfo, ok := app.tunnelRateMap[tunName]; ok {
        for Attr := range tunRateInfo.entry.Field {
            switch Attr {
            case "RX_BPS":
				rx_bps_ptr := new(string)
                *rx_bps_ptr = tunRateInfo.entry.Get(Attr)
                ctrInfo.InBps = rx_bps_ptr

			case "RX_PPS":
				rx_pps_ptr := new(string)
                *rx_pps_ptr = tunRateInfo.entry.Get(Attr)
                ctrInfo.InPps = rx_pps_ptr

			case "TX_BPS":
                tx_bps_ptr := new(string)
                *tx_bps_ptr = tunRateInfo.entry.Get(Attr)
                ctrInfo.OutBps = tx_bps_ptr

			case "TX_PPS":
				tx_pps_ptr := new(string)
                *tx_pps_ptr = tunRateInfo.entry.Get(Attr)
                ctrInfo.OutPps = tx_pps_ptr
			}
        }
    }
}

func (app *VxlanApp)constructTunnelIfsCounterOCInfo(
                        vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan,
                        dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
	isVM := is_Platform_VM()

	if isVM == false {
        /* Filling the tunnel counter Info to internal DS */
        app.appDB = dbs[db.ConfigDB]
        err = app.getTunCtrPollIntFromDB(app.appDB)
        if err == nil {
            err = app.getTunnelOidMapForCounters(app.countersDB)
            if err != nil {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, err
            }
            err = app.getTunnelCounterInfoFromDB(app.countersDB, "", db.Key{})
            if err != nil {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, err
            }
        }
    }

    countersInfo := vxlanObj.Counters
    ygot.BuildEmptyTree(countersInfo)

    app.getTunCtrPollIntervalFromInternalMap(countersInfo)

	for tunnelName := range app.tunnelOidMap.entry.Field {
        log.Info("tunnelName = ", tunnelName)
        counterInfo, err := countersInfo.NewCounter(tunnelName)
        if err != nil {
            log.Errorf("Creation of tunnel counter subtree for %s failed!", tunnelName)
            return GetResponse{Payload: payload, ErrSrc: AppErr}, err
        }
        ygot.BuildEmptyTree(counterInfo)
        app.getTunnelCounterInfoFromInternalMap(tunnelName, counterInfo)
    }
    payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))

    return GetResponse{Payload: payload}, err
}

func (app *VxlanApp)constructTunnelIfCounterOCInfo(targetUriPath string,
                        vxlanObj *ocbinds.OpenconfigVxlanCls_Vxlan, dbs [db.MaxDB]*db.DB) (GetResponse, error) {
    var err error
    var payload []byte
    var resp GetResponse
    pathInfo := app.path

    isVM := is_Platform_VM()

    if vxlanObj.Counters == nil {
        err = tlerr.NotSupported("Counters container is nil.")
        return GetResponse{Payload: payload, ErrSrc: AppErr}, err
    }

    // Get request for a vxlan tunnel interface counters
    if vxlanObj.Counters.Counter != nil && len(vxlanObj.Counters.Counter) > 0 &&
                pathInfo.HasVar("tun-if-name") == true {
        log.Info("Get a specific vxlan tunnel interface counter request!")

        tunIfName := pathInfo.Var("tun-if-name")
        log.Infof("tunIfName = %s", tunIfName)

        if isVM == false {
            /* Filling the tunnel counter Info to internal DS */
            app.appDB = dbs[db.ConfigDB]
            err = app.getTunCtrPollIntFromDB(app.appDB)
            if err == nil {
                err = app.getTunnelOidMapForCounters(app.countersDB)
                if err != nil {
                    return GetResponse{Payload: payload, ErrSrc: AppErr}, err
                }
                err = app.getTunnelCounterInfoFromDB(app.countersDB, tunIfName, asKey(tunIfName))
                if err != nil {
                    return GetResponse{Payload: payload, ErrSrc: AppErr}, err
                }
            }
        }

        // Check if the request is for a specific attribute in tunnel counter container
        ocCounter := &ocbinds.OpenconfigVxlanCls_Vxlan_Counters_Counter{}
        ok, e :=  app.getTunnelCounterInfoSpecificAttr(targetUriPath, tunIfName, ocCounter)
        if ok {
            if e != nil {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, e
            }
            payload, err = dumpIetfJson(ocCounter)
            if err == nil {
                return GetResponse{Payload: payload}, err
            } else {
                return GetResponse{Payload: payload, ErrSrc: AppErr}, err
            }
        }

        counterInfo := vxlanObj.Counters.Counter[tunIfName]
        ygot.BuildEmptyTree(counterInfo)

        app.getTunCtrPollIntervalFromInternalMap(vxlanObj.Counters)
        app.getTunnelCounterInfoFromInternalMap(tunIfName, counterInfo)

        // Dump the contents, if get request is valid
        if *app.ygotTarget == counterInfo {
            payload, err = dumpIetfJson((*app.ygotRoot).(*ocbinds.Device))
        } else {
            log.Info("Not supported get type!")
            err = tlerr.NotSupported("Requested get-type not supported!")
        }
        resp = GetResponse{Payload: payload}
    } else {
        log.Info("Get all tunnels counter(without key) request!")
        resp, err = app.constructTunnelIfsCounterOCInfo(vxlanObj, dbs)
    }
    return resp, err
}

func (app *VxlanApp)translateVxlanVniMapConfigToDB(d *db.DB, op int,vrfname string,oc_val *ocbinds.OpenconfigVxlanCls_Vxlan) ([]db.WatchKeys, error) {
    log.Info("translateVxlanVniMapConfigToDB")
    var err error = nil
    var keys []db.WatchKeys
    var entry dbEntry
    var updateDB bool

    updateDB = false
    entry.op = op
    entry.ts = app.VrfTs
    entry.key = asKey(vrfname)
    curr, err := d.GetEntry(entry.ts, entry.key)

    if op == CREATE {
        if curr.IsPopulated() {
            log.Error("Vrf entry exists already")
            return keys, tlerr.AlreadyExists("Vrf entry exists already.")
        } else {
            curr = db.Value{Field: make(map[string]string)}
        }
    }
    if err != nil && op == UPDATE {
        log.Infof("Vrf entry not found, creating it")
        entry.op = CREATE
        curr = db.Value{Field: make(map[string]string)}
        err = nil
    }

    if oc_val.Config != nil {
        if oc_val.Config.VniVrf[vrfname] != nil {
            log.Info("VniMapVniId:", *oc_val.Config.VniVrf[vrfname].VniMapVniId)
            if app.VlanVniMapped(d,*oc_val.Config.VniVrf[vrfname].VniMapVniId) == false {
                return nil,tlerr.NotFound("VLAN VNI not mapped. Please create VLAN VNI map entry first")
            }
            vrf_vni_mapped := app.VrfVniMapped(d,*oc_val.Config.VniVrf[vrfname].VniMapVniId)
            if vrf_vni_mapped != ""{
                return nil,tlerr.NotFound("VNI already mapped to %s",vrf_vni_mapped)
            }
            curr.Field["vni"] = strconv.FormatUint(*oc_val.Config.VniVrf[vrfname].VniMapVniId,10)
        }
        updateDB = true
    }
    log.Infof("Translated DB entry [op:%d][table:%s][key:%s] updateDB:%t",entry.op, entry.ts.Name, entry.key, updateDB)
    entry.entry = curr

    if updateDB == true {
        app.VrfTableMap[vrfname] = entry
    }
    return keys, err
}

func (app *VxlanApp) VlanVniMapped(d *db.DB, vni uint64) (bool) {
    ts := &db.TableSpec{Name: "VXLAN_TUNNEL_MAP"}
    keys, err := d.GetKeys(ts)
    if err != nil {
        return false
    }
    for i, _ := range keys {
        vxlan_tunnel,_ := d.GetEntry(ts,keys[i])
        if vxlan_tunnel.IsPopulated() && vxlan_tunnel.Get("vni") == strconv.FormatUint(vni,10) {
            return true
        }
    }
    return false
}

func (app *VxlanApp) VrfVniMapped(d *db.DB, vni uint64) (string) {
    ts := &db.TableSpec{Name: VRF }
    keys, err := d.GetKeys(ts)
    if err != nil {
        return ""
    }
    for i, _ := range keys {
        vrf,_ := d.GetEntry(ts,keys[i])
        if vrf.IsPopulated() && vrf.Get("vni") == strconv.FormatUint(vni,10) {
            return keys[i].Get(0)
        }
    }
    return ""
}

func (app *VxlanApp) handleVxlanVniVrfMapConfigDelete(d *db.DB,vrfname string) ([]db.WatchKeys, error) {
    var err error
    var keys []db.WatchKeys
    var entry dbEntry
    var updateDB = false
    entry.key = asKey(vrfname)
    entry.ts = app.VrfTs
    entry.op = UPDATE
    curr, err := d.GetEntry(entry.ts, entry.key)
    if err != nil {
        //entry not found
        return keys,nil
    }
    if curr.IsPopulated() && curr.Has("vni"){
            curr.Field["vni"] = "0"
            updateDB = true
            entry.entry = curr
    }

    log.Infof("Translated DB entry [op:%d][table:%s][key:%s]",entry.op, entry.ts.Name, entry.key)
    if updateDB{
        app.VrfTableMap[vrfname] = entry
    }

    return keys, err
}
