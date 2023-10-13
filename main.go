package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"fmt"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"
)

// type varuint uint64
const (
	SMARTHUB  = 0x01
	EnvSensor = 0x02
	Switch    = 0x03
	Lamp      = 0x04
	Socket    = 0x05
	Clock     = 0x06
)
const All = 0x3FFF
const NameHub = "SmartHub"
const (
	GET       = 0x00
	WHOISHERE = 0x01
	TICK      = 0x06
	IAMHERE   = 0x02
	GETSTATUS = 0x03
	STATUS    = 0x04
	SETSTATUS = 0x05
)

type packet struct {
	length  byte
	payload []byte
	src8    byte
}

type PayloadQueue struct{
	queue []payload
}

func (pq *PayloadQueue) Push(pld payload){
	pq.queue = append(pq.queue, pld)
}

func (pq *PayloadQueue) Take() payload{
	front := pq.queue[0]
	pq.queue = pq.queue[1:]
	return front
}

func (pq *PayloadQueue) Size() int {
	return len(pq.queue)
}
type payload struct {
	src      uint64
	dst      uint64
	serial   uint64
	dev_type byte
	cmd      byte
	cmd_body []byte
}

type device struct {
	dev_name  string
	dev_props []byte
}

type timer_cmd_body struct {
	timestamp uint64
}

type env_sensor_props struct {
	sensors  byte
	triggers []struct {
		op    byte
		value uint64
		name  string
	}
}
type Triggers struct{
	eq    bool
	more bool
	typeSensor byte
	op    byte
	value uint64
	name  string
}
type env_sensor_status_cmd_body struct {
	values []uint64
}
type dev struct {
	src      uint64
	dev_type byte
}
type SmartHub struct{
	url string
	id uint64
	serial uint64
	devices map[string]dev
	namesOfDev map[uint64]string
	connectionDevs []string
	sensors [4]bool
	triggers []Triggers
	plsdQ    PayloadQueue
}
type MyError struct {
	err    error
	code int
}

func(err MyError) Error() string{
	return fmt.Sprintf("error: ", err.err, "; code:", err.code)
}

func main() {
	args := os.Args[1:]
	var target MyError
	num, _ := strconv.ParseInt(args[1],0,64)
	CalculateTable_CRC8()
	smartHub := SmartHub{url: args[0], id: uint64(num), serial: 1, devices: make(map[string]dev), namesOfDev: make(map[uint64]string)}
	err := smartHub.WhoIsHere()
	if errors.As(err, &target){
		if target.err == nil && target.code == http.StatusNoContent{
			os.Exit(0)
		} else {
			os.Exit(99)
		}
	}


	for {
		length := smartHub.plsdQ.Size()
		for i:=0; i<length; i++{
			task := smartHub.plsdQ.Take()
			err = smartHub.SendMess(task)
			if errors.As(err, &target){
				if target.err == nil && target.code == http.StatusNoContent{
					os.Exit(0)
				} else {
					os.Exit(99)
				}
			}
		}

		err = smartHub.emptyRequest()
		if errors.As(err, &target){
			if target.err == nil && target.code == http.StatusNoContent{
				os.Exit(0)
			} else {
				os.Exit(99)
			}
		}

	}
}

func (smartHub *SmartHub)WhoIsHere() error {
	  device := EncodeDevice(device{dev_name: NameHub})
	  payload := payload{src: smartHub.id, dst: All, serial: smartHub.serial, dev_type: SMARTHUB, cmd: WHOISHERE, cmd_body: device}
	  return smartHub.SendMess(payload)
}

func (smartHub *SmartHub) PostRequest(strBase64 string, dstAddr uint64, sentCmd byte, hasAns *bool, firstTime *uint64)(bool, error){
	resp, err := http.Post(smartHub.url, "text/plain", strings.NewReader( Base_encode(strBase64)))
	if err != nil || (resp.StatusCode != 200) {
		return false, MyError{err: err, code: resp.StatusCode}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	pkts, err := Decode(string(body))
	if err != nil {
		fmt.Println(err)
	}
	plds := DecodePayloads(pkts)
	for i:=0; i < len(plds); i++{
		time, ok, src := smartHub.Pr(plds[i], sentCmd)
		if src == dstAddr{
			*hasAns = true
		}
		if *firstTime == 0 && ok {
			*firstTime = time
		}
	
		if ok && time - *firstTime >= 300{
			if !(*hasAns){
					delete(smartHub.devices, smartHub.namesOfDev[dstAddr])
					delete(smartHub.namesOfDev, dstAddr)
				}
				return false, nil
		}
	}
		
	return true, nil
}




func encodeULEB128(n uint64) []byte {
	var result []byte
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		result = append(result, b)
		if n == 0 {
			break
		}
	}
	return result
}
func decodeULEB128(data []byte) int {
	var result int
	var shift uint

	for _, b := range data {
		result |= int(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}

	return result
}
func decodeULEB128Payload(b *bytes.Reader) uint64 {
	var result uint64
	var shift uint
	for {
		byteVal, _ := b.ReadByte()
		result |= uint64(byteVal&0x7F) << shift
		if byteVal&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result
}
func EncodePacket(packect packet) string {
	var mess []byte
	mess = append(mess, packect.length)
	mess = append(mess, packect.payload...)
	mess = append(mess, packect.src8)
	return base64.RawURLEncoding.EncodeToString(mess)
}
func Decode(str string) ([]packet, error) {
	ans := make([]packet, 0)
	mess, _ := base64.RawURLEncoding.DecodeString(str)
	b := bytes.NewReader(mess)
	for b.Len() > 0 {
		var pkt packet
		pkt.length, _ = b.ReadByte()
		for i := 0; i < int(pkt.length); i++ {
			readByte, _ := b.ReadByte()
			pkt.payload = append(pkt.payload, readByte)
		}
		pkt.src8, _ = b.ReadByte()
		if ComputeCRC8(pkt.payload) == pkt.src8 {
			ans = append(ans, pkt)
		}
	}
	return ans, nil
}
func EncodePayload(p payload) []byte {
	mess := make([]byte, 0)
	mess = append(mess, encodeULEB128(p.src)...)
	mess = append(mess, encodeULEB128(p.dst)...)
	mess = append(mess, encodeULEB128(p.serial)...)
	mess = append(mess, p.dev_type)
	mess = append(mess, p.cmd)
	mess = append(mess, p.cmd_body...)
	return mess
}
func DecodePayloads(pkts []packet) []payload {
	ans := make([]payload, 0)
	for i := 0; i < len(pkts); i++ {
		var pld payload
		b := bytes.NewReader(pkts[i].payload)
		pld.src = (decodeULEB128Payload(b))
		pld.dst = (decodeULEB128Payload(b))
		pld.serial = (decodeULEB128Payload(b))
		pld.dev_type, _ = b.ReadByte()
		pld.cmd, _ = b.ReadByte()
		for b.Len() > 0 {
			k, _ := b.ReadByte()
			pld.cmd_body = append(pld.cmd_body, k)
		}
		ans = append(ans, payload{src: pld.src, dst: pld.dst, serial: pld.serial, dev_type: pld.dev_type, cmd: pld.cmd, cmd_body: pld.cmd_body})
	}
	return ans
}
func EncodeDevice(device device) []byte {
	resDev := make([]byte, 0)
	resDev = append(resDev, byte(len(device.dev_name)))
	resDev = append(resDev, []byte(device.dev_name)...)
	resDev = append(resDev, device.dev_props...)
	return resDev
}
func DecodeTimer(b []byte) timer_cmd_body {
	resTick := decodeULEB128(b)
	var timer timer_cmd_body
	timer.timestamp = uint64(resTick)
	return timer
}

func DecodeValue(b []byte) byte {
	bt := bytes.NewReader(b)
	value, _ := bt.ReadByte()
	return value
}
func DecodeDevice(b []byte) device {
	var devRes device
	if len(b) > 0 {
		len := int(b[0])
		devRes.dev_name = string(b[1 : len+1])
		devRes.dev_props = b[len+1:]
		return devRes
	}
	return device{}
}

func DecodeSensorProps(b []byte) env_sensor_props {
	bSP := bytes.NewReader(b)
	var envSensorProps env_sensor_props
	length, _ := bSP.ReadByte()
	envSensorProps.triggers = make([]struct{op byte; value uint64; name string}, length)
	for i := 0; i < int(length); i++ {
		envSensorProps.triggers[i].op, _ = bSP.ReadByte()
		envSensorProps.triggers[i].value = decodeULEB128Payload(bSP)
		lenSTR, _ := bSP.ReadByte()
		str := make([]byte, lenSTR)
		for j := 0; j < int(lenSTR); j++ {
			str[j], _ = bSP.ReadByte()
		}
		envSensorProps.triggers[i].name = string(str)
	}
	return envSensorProps
}
func DecodeEnvSensorsStatusCmdBode(b []byte) env_sensor_status_cmd_body {
	var envSensorsCmdBody env_sensor_status_cmd_body
	bESSCB := bytes.NewReader(b)
	length, _ := bESSCB.ReadByte()
	envSensorsCmdBody.values = make([]uint64, length)
	for i := 0; i < int(length); i++ {
		envSensorsCmdBody.values[i] = decodeULEB128Payload(bESSCB)
	}
	return envSensorsCmdBody

}
func ByteToString(bts []byte) []string {
	b := bytes.NewReader(bts)
	ans := make([]string, 0)
	_, _ = b.ReadByte()
	for b.Len() > 0 {
		length, _ := b.ReadByte()
		str := make([]byte, 0)
		for i := 0; i < int(length); i++ {
			bt, _ := b.ReadByte()
			str = append(str, bt)
		}
		ans = append(ans, string(str))
	}
	return ans
}

var crctable = make([]byte, 256)
var generator byte = 0x1D

func CalculateTable_CRC8() {

	for dividend := 0; dividend < 256; dividend++ {
		currByte := byte(dividend)

		for bit := 0; bit < 8; bit++ {
			if (currByte & 0x80) != 0 {
				currByte <<= 1
				currByte ^= generator
			} else {
				currByte <<= 1
			}
		}

		crctable[dividend] = currByte
	}
}

func ComputeCRC8(bytes []byte) byte {
	crc := byte(0)
	for _, b := range bytes {
		data := b ^ crc
		crc = crctable[data]
	}

	return crc
}
func Base_encode(s string) string {
	col := utf8.RuneCountInString(s)
	if string(s[col-2:]) == "==" {
		s = strings.TrimSuffix(s, "==")
	} else if string(s[col-1]) == "=" {
		s = strings.TrimSuffix(s, "=")
	}
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "+", "-")

	return s
}
func parseByte(f byte) (bool, bool, byte) {
	equivalent := f&0x1 != 0
	more := f&0x2 != 0
	sensorType := f >> 2 & 0x3
	return equivalent, more, sensorType
}

func (smartHub *SmartHub) Pr(pld payload, sentCmd byte) (uint64, bool, uint64){
	switch pld.cmd{
	case WHOISHERE:
		smartHub.AddDevice(pld)
		payload := EncodePayload(payload{src: smartHub.id, dst: All, serial: smartHub.serial, dev_type: SMARTHUB, cmd: IAMHERE, cmd_body: EncodeDevice(device{dev_name: NameHub})})
		packet := packet{
			length:  byte(len(payload)),
			payload: payload,
			src8:    ComputeCRC8(payload),
		}
		smartHub.serial++
		_,_ = http.Post(smartHub.url, "text/plain", strings.NewReader(EncodePacket(packet)))
	case IAMHERE:
		if sentCmd == WHOISHERE{
			smartHub.AddDevice(pld)
		}
	case STATUS:
		if _, ok := smartHub.namesOfDev[pld.src]; ok{
			switch pld.dev_type{
			case Switch:
				mode := pld.cmd_body[0]
				for i:=0; i< len(smartHub.connectionDevs); i++{
					if dev, ok := smartHub.devices[smartHub.connectionDevs[i]]; ok {
						smartHub.plsdQ.Push(payload{src: smartHub.id, dst: dev.src, serial: smartHub.serial, dev_type: dev.dev_type, cmd: SETSTATUS, cmd_body: []byte{mode}})
					}
				}
			case EnvSensor:
				smartHub.CheckTriggers(pld)
			}
		}
	case TICK:
		decoded := DecodeTimer(pld.cmd_body)
		return decoded.timestamp, true, pld.src
	}
	return 0 , false, pld.src

}

func(smartHub *SmartHub) CheckTriggers(pld payload){
	envSensorStatus := DecodeEnvSensorsStatusCmdBode(pld.cmd_body)
	var valuesSensor [4]uint64
	j:=0
	for i:= range smartHub.sensors{
		if smartHub.sensors[i]{
			valuesSensor[i] = envSensorStatus.values[j]
			j++
		}
	}
	for _, trigger := range smartHub.triggers{
		mode := byte(0)
		if trigger.eq{
			mode =1
		}
		if _, ok:= smartHub.devices[trigger.name]; ok && smartHub.sensors[trigger.typeSensor]{
			if trigger.more && valuesSensor[trigger.typeSensor] > trigger.value || !trigger.more && valuesSensor[trigger.typeSensor]< trigger.value{
			smartHub.plsdQ.Push(payload{src: smartHub.id, dst: smartHub.devices[trigger.name].src, serial: smartHub.serial, dev_type: smartHub.devices[trigger.name].dev_type, cmd: SETSTATUS, cmd_body: []byte{mode}})
			
		}
	}
}
}

func (smartHub *SmartHub) AddDevice(pld payload){
   decoded := DecodeDevice(pld.cmd_body)
   smartHub.devices[decoded.dev_name] = dev{src: pld.src, dev_type: pld.dev_type}
   smartHub.namesOfDev[pld.src]= decoded.dev_name
   switch pld.dev_type{
   case Switch:
	smartHub.connectionDevs = ByteToString(decoded.dev_props)
	smartHub.plsdQ.Push(payload{src: smartHub.id, dst: pld.src, serial: smartHub.serial, dev_type: Switch,cmd:GETSTATUS})
   case EnvSensor:
	envSensor := DecodeSensorProps(decoded.dev_props)

	smartHub.sensors[0] = envSensor.sensors&0x1 != 0
	smartHub.sensors[1] = envSensor.sensors&0x2 != 0
	smartHub.sensors[2] = envSensor.sensors&0x4 != 0
	smartHub.sensors[3] = envSensor.sensors&0x8 != 0

	smartHub.triggers = make([]Triggers, len(envSensor.triggers))
	for i:= 0; i< len(envSensor.triggers); i++{
		smartHub.triggers[i].eq, smartHub.triggers[i].more, smartHub.triggers[i].typeSensor = parseByte(envSensor.triggers[i].op)
		smartHub.triggers[i].value = envSensor.triggers[i].value
		smartHub.triggers[i].name = envSensor.triggers[i].name
	}
      smartHub.plsdQ.Push(payload{src: smartHub.id, dst: pld.src, serial: smartHub.serial, dev_type: EnvSensor, cmd: GETSTATUS})
   }

}

func (smartHub *SmartHub) SendMess(pld payload) error{
	bytesPld := EncodePayload(pld)
	hasAnswer := pld.dst == All
	var firstTime uint64
	packet:=packet{
		length: byte(len(bytesPld)),
		payload: bytesPld,
		src8: ComputeCRC8(bytesPld),
	}
	smartHub.serial++
	ok, err := smartHub.PostRequest(EncodePacket(packet), pld.dst, pld.cmd, &hasAnswer, &firstTime)
	for ok {
		ok, err = smartHub.PostRequest("",pld.dst, pld.cmd, &hasAnswer, &firstTime)
	}
	return err
}

func (smartHub *SmartHub) emptyRequest() error{
	resp, err := http.Post(smartHub.url, "text/plain", strings.NewReader(""))
	if err != nil || (resp.StatusCode != 200) {
		return MyError{err: err, code: resp.StatusCode}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	pkts,_ := Decode(string(body))
	plds := DecodePayloads(pkts)
	for i :=0 ; i< len(plds); i++{
		_,_,_ = smartHub.Pr(plds[i], GET)
	}
	return nil
}