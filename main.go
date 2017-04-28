// bincrawl written by Scott Glover 

package main

 import (
	 "encoding/binary"
         "bytes"
	 "encoding/base64"
         "flag"
         "fmt"
         "io/ioutil"
	 "regexp"
         "math"
         "os"
         "strconv"
         "strings"
 )

 const fileChunk = 8192

var inValue = flag.String("invalue", "", "Value to scan file for")
var inForm = flag.String("inform", "str", "Data format of invalue (b64, hex, str)")
var fileToScan = flag.String("filename", "", "Name of file to scan.")
var scanPem = flag.Bool("scanpem", false, "Scan for PEM format cert in file")
var scanBase64 = flag.Bool("scanb64", false, "Scan for strings which match Base64 encoded requirements")

 func main() {
         flag.Parse()

         if (*fileToScan == "") {
             flag.PrintDefaults()
             os.Exit(0)
         }

         fmt.Printf("Scanning %s....\n", *fileToScan)

         file, err := os.Open(*fileToScan)
         if err != nil {
                 fmt.Println("Unable to open file : ", err)
                 os.Exit(-1)
         }

         defer file.Close()

         // calculate the file size
         info, _ := file.Stat()

         filesize := info.Size()

         blocks := uint64(math.Ceil(float64(filesize) / float64(fileChunk)))

	// matches base64 strings
	r, _ := regexp.Compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})")

	r2, _ := regexp.Compile("-+BEGIN CERTIFICATE-+\n(?:[^-]*\n)+-+END CERTIFICATE-+")
	r3, _ := regexp.Compile("-+BEGIN RSA (PRIVATE|PUBLIC) KEY-+\n(?:[^-]*\n)+-+END RSA (PRIVATE|PUBLIC) KEY-+")

         // we scan the file for Signature block by block
         for i := uint64(0); i < blocks; i++ {

                 blocksize := int(math.Min(fileChunk, float64(filesize-int64(i*fileChunk))))
                 buf := make([]byte, blocksize)

                 //fmt.Printf("Scanning block #%d , size of %d\n", i, blocksize)

                 file.Read(buf)
		 if bytes.Contains(buf, []byte("\x30\x82")) {
			var length uint16
			//curpos := 0
			//while true {
			pos := bytes.Index(buf, []byte("\x30\x82"))
			if bytes.Equal(buf[pos+4:pos+6], []byte("\x30\x82")) {
				err := binary.Read(bytes.NewReader(buf[pos+2:pos+4]), binary.BigEndian, &length)
				if err != nil {
					fmt.Println("binary.Read failed:", err)
				}
				fmt.Printf("Found DER cert: %d\n", length)
			}
			//}
		 }
		 // scan for PEM format cert
		 if *scanPem && r2.MatchString(string(buf)) {
			for _, each := range r2.FindAllString(string(buf),-1) {
				ioutil.WriteFile("data/"+strconv.FormatUint(i, 10)+".cer", []byte(each), 0644)
				fmt.Println(each)
			}
		 }

                 // scan for PEM format RSA public/private key
                 if *scanPem && r3.MatchString(string(buf)) {
                        for _, each := range r3.FindAllString(string(buf),-1) {
                                ioutil.WriteFile("data/"+strconv.FormatUint(i, 10)+".cer", []byte(each), 0644)
                                fmt.Println(each)
                        }
                 }


		 if *scanBase64 && r.MatchString(string(buf)) {
			// scan for strings which look like base64, then verify that it is base64
			var str = strings.Replace(string(buf), "\n", "", -1)
			for _, each := range r.FindAllString(str,-1) {
			        _, err := base64.StdEncoding.DecodeString(each)
				if err == nil && len(each) > 32 {
					//fmt.Println(each)
				}
			}
		 }
         }
 }
