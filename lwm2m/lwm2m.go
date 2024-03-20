package lwm2m

type LwM2MObjectID uint16

const (
	Geolocation_14201           LwM2MObjectID = 14201
	BatteryAndPower_14202       LwM2MObjectID = 14202
	ConnectionInformation_14203 LwM2MObjectID = 14203
	DeviceInformation_14204     LwM2MObjectID = 14204
	Environment_14205           LwM2MObjectID = 14205
	SolarCharge_14210           LwM2MObjectID = 14210
	ButtonPress_14220           LwM2MObjectID = 14220
	SeaWaterLevel_14230         LwM2MObjectID = 14230
)

type LwM2MObjectInstance struct {
	ObjectID      LwM2MObjectID
	ObjectVersion string
	Resources     map[string]interface{}
}
