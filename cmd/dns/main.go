package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

type Header struct {
	Id       uint16
	Flags    uint16
	QdCount  uint16
	AnsCount uint16
	NsCount  uint16
	ArCount  uint16
}

const ROOT_DNS_SERVER = "192.36.148.17"

func (header Header) Encode() []byte {
	headerBytes := make([]byte, 12) // 12 is the number of bytes in header as per https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
	binary.BigEndian.PutUint16(headerBytes[0:], header.Id)
	binary.BigEndian.PutUint16(headerBytes[2:], header.Flags)
	binary.BigEndian.PutUint16(headerBytes[4:], header.QdCount)
	binary.BigEndian.PutUint16(headerBytes[6:], header.AnsCount)
	binary.BigEndian.PutUint16(headerBytes[8:], header.NsCount)
	binary.BigEndian.PutUint16(headerBytes[10:], header.ArCount)
	return headerBytes
}

func (header *Header) decode(headerBytes []byte) {
	err := binary.Read(bytes.NewReader(headerBytes), binary.BigEndian, header)
	if err != nil {
		fmt.Println("Error converting to struct:", err)
	}
}

type Question struct {
	Name  string
	QType uint16
	Class uint16
}

func (question Question) Encode() []byte {
	questionBytes := make([]byte, 0) // the number of bytes in question vary as per question name
	questionBytes = append(questionBytes, []byte(question.Name)...)
	questionBytes = append(questionBytes, make([]byte, 4)...)
	binary.BigEndian.PutUint16(questionBytes[len(questionBytes)-4:], question.QType)
	binary.BigEndian.PutUint16(questionBytes[len(questionBytes)-2:], question.Class)
	return questionBytes
}

func (question *Question) decode(questionBytes []byte) int {
	var name string
	idx := 0
	var length int
	for idx < len(questionBytes) {
		length = int(questionBytes[idx])
		if length == 0 {
			break
		}
		if idx != 0 {
			name = name + "."
		}
		name = name + string(questionBytes[idx+1:idx+1+length])
		idx = idx + length + 1
	}
	length = len([]byte(name))
	length = length + 2 // 2 bytes for ending 0
	question.Name = name
	question.QType = binary.BigEndian.Uint16(questionBytes[length : length+2])
	question.Class = binary.BigEndian.Uint16(questionBytes[length+2 : length+4])
	return length + 4
}

func decodeDomainName(bytes []byte, startPos int) (int, string) {
	nameByteLength := 0
	var name string
	idx := startPos
	var length int
	shouldIncreasePointer := false
	for idx < len(bytes) {
		length = int(bytes[idx])
		if length >= 192 { //val greater than 192 indicates a pointer
			idx = int(bytes[idx+1])
			shouldIncreasePointer = true
		} else {
			if length == 0 {
				break
			}
			name = name + string(bytes[idx+1:idx+length+1])
			name = name + "."
			idx = idx + 1 + length
		}
	}
	if name != "" {
		name = name[:len(name)-1]
	}
	if shouldIncreasePointer {
		nameByteLength = 2 //if it was a pointer its just 2
	} else {
		nameByteLength = len([]byte(name)) + 2 //2 for truncating 0
	}
	return nameByteLength, name
}

func (resourceRec *Record) decode(bytes []byte, startPos int) int {
	nameByteLength, name := decodeDomainName(bytes, startPos)
	resourceRec.Name = name
	resourceRec.Type = binary.BigEndian.Uint16(bytes[startPos+nameByteLength : startPos+nameByteLength+2])
	resourceRec.Class = binary.BigEndian.Uint16(bytes[startPos+nameByteLength+2 : startPos+nameByteLength+4])
	resourceRec.ttl = binary.BigEndian.Uint32(bytes[startPos+nameByteLength+4 : startPos+nameByteLength+8])
	resourceRec.rdlength = binary.BigEndian.Uint16(bytes[startPos+nameByteLength+8 : startPos+nameByteLength+10])

	var rDataBytes []byte
	if resourceRec.Type == 1 { //Type 1 means A record, so it's a IPv4 address
		rDataBytes = bytes[startPos+nameByteLength+10 : startPos+nameByteLength+10+int(resourceRec.rdlength)]
		resourceRec.rdata = fmt.Sprintf("%d.%d.%d.%d", rDataBytes[0], rDataBytes[1], rDataBytes[2], rDataBytes[3])
	} else if resourceRec.Type == 2 {
		_, name := decodeDomainName(bytes, startPos+nameByteLength+10)
		resourceRec.rdata = name
	}
	//
	//println("name ", resourceRec.Name)
	//println("rdata ", resourceRec.rdata)
	//println("Type ", resourceRec.Type)
	//println("Class ", resourceRec.Class)

	return nameByteLength + 10 + int(resourceRec.rdlength)
}

type Record struct {
	Name     string
	Type     uint16
	Class    uint16
	ttl      uint32
	rdlength uint16
	rdata    string
}

func encodeDomainName(domain string) []byte {
	parts := strings.Split(domain, ".")
	var encoded []byte
	for _, part := range parts {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, []byte(part)...)
	}
	encoded = append(encoded, 0)
	return encoded
}

func resolveDomainName(domainName string, dnsServer string) (*[]string, error) {
	var ips []string
	fmt.Printf("Querying %s for %s\n", dnsServer, domainName)
	headerReq := Header{
		Id:       44,
		Flags:    0,
		QdCount:  1,
		AnsCount: 0,
		NsCount:  0,
		ArCount:  0,
	}
	headerBytes := headerReq.Encode()
	queReq := Question{
		Name:  string(encodeDomainName(domainName)),
		QType: 1,
		Class: 1,
	}

	queBytes := queReq.Encode()
	messageBytes := append(headerBytes, queBytes...)

	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", dnsServer, "53"))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error resolving address: %s", err))
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error connecting: %s", err))
	}
	defer conn.Close()

	_, err = conn.Write(messageBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error ending message: %s", err))
	}
	buffer := make([]byte, 512)
	_, _, err = conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error receiving response: %s", err))
	}

	//parsing header
	headerByteLength := 12
	header := Header{}
	header.decode(buffer[0:headerByteLength])
	qr := qrDecode(header)
	if qr != "1" { //QR as 1 represents response
		return nil, errors.New(fmt.Sprintf("Not a  response"))
	}

	//parsing question
	question := Question{}
	queByteLength := question.decode(buffer[headerByteLength:])
	var counter uint16 = 0
	resourceRecordStartPos := headerByteLength + queByteLength

	var answerRecords []Record
	//parsing answers
	//fmt.Printf("-------------parsing %v answerRec-------------\n", header.AnsCount)
	for counter < header.AnsCount {
		answerRec := Record{}
		ansByteLength := answerRec.decode(buffer, resourceRecordStartPos)
		resourceRecordStartPos = resourceRecordStartPos + ansByteLength
		answerRecords = append(answerRecords, answerRec)
		counter++
	}

	if len(answerRecords) > 0 {
		for _, val := range answerRecords {
			ips = append(ips, val.rdata)
		}
		return &ips, nil
	}

	//parsing authorities
	counter = 0
	//fmt.Printf("-------------parsing %v authorityRecords-------------\n", header.NsCount)
	var authorityRecords []Record
	for counter < header.NsCount {
		authorityRec := Record{}
		authorityByteLength := authorityRec.decode(buffer, resourceRecordStartPos)
		resourceRecordStartPos = resourceRecordStartPos + authorityByteLength
		authorityRecords = append(authorityRecords, authorityRec)
		counter++
	}

	//parsing additionalRecords
	counter = 0
	//fmt.Printf("-------------parsing %v additionalRecords-------------\n", header.ArCount)
	var additionalRecords []Record
	for counter < header.ArCount {
		additionalRec := Record{}
		authorityByteLength := additionalRec.decode(buffer, resourceRecordStartPos)
		resourceRecordStartPos = resourceRecordStartPos + authorityByteLength
		additionalRecords = append(additionalRecords, additionalRec)
		counter++
	}

	if len(additionalRecords) > 0 {
		var counter = 0
		for counter < len(additionalRecords) {
			if additionalRecords[counter].Type == 1 { // Type 1 is an A record, i.e. its an address
				name, err := resolveDomainName(domainName, additionalRecords[counter].rdata)
				if err != nil {
					return nil, err
				}
				return name, err
			}
			counter++
		}
	}

	if len(authorityRecords) > 0 {
		var nsServerIp *[]string
		var counter = 0
		for counter < len(authorityRecords) {
			if authorityRecords[counter].Type == 2 { // Type 2 is an NS record
				nsServerIp, err = resolveDomainName(authorityRecords[counter].rdata, ROOT_DNS_SERVER)
				if err != nil {
					return nil, err
				}
				break
			}
			counter++
		}
		if nsServerIp != nil {
			for _, test := range *nsServerIp {
				nsServerIp1, err := resolveDomainName(domainName, test)
				if err != nil {
					return nil, err
				}
				return nsServerIp1, nil
			}

		}
	}

	return &ips, errors.New(fmt.Sprintf("** Could not find %s **\n", domainName))

}

func main() {
	domainName := os.Args[1]
	name, err := resolveDomainName(domainName, ROOT_DNS_SERVER)
	if err != nil {
		println("err ", err.Error())
		return
	}
	println("Here is what we found")
	for _, val := range *name {
		println(val)
	}
}

func qrDecode(res Header) string {
	binaryFlags := fmt.Sprintf("%b", res.Flags)
	return string(binaryFlags[0])
}
