// bincrawl written by Scott Glover 

package main

 import (
//         "bytes"
	 "encoding/base64"
         "fmt"
         "io/ioutil"
	 "regexp"
         "math"
         "os"
         "strconv"
         "strings"
 )

 const fileChunk = 8192

 func main() {
         if len(os.Args) != 2 {
                 fmt.Printf("Usage : %s <filename to scan> \n", os.Args[0])
                 os.Exit(0)
         }

         fileToScan := os.Args[1]

         fmt.Printf("Scanning %s....\n", fileToScan)

         file, err := os.Open(fileToScan)
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

         // we scan the file for Signature block by block
         for i := uint64(0); i < blocks; i++ {

                 blocksize := int(math.Min(fileChunk, float64(filesize-int64(i*fileChunk))))
                 buf := make([]byte, blocksize)

                 //fmt.Printf("Scanning block #%d , size of %d\n", i, blocksize)

                 file.Read(buf)

		 // scan for PEM format cert
		 if r2.MatchString(string(buf)) {
			for _, each := range r2.FindAllString(string(buf),-1) {
				ioutil.WriteFile("data/"+strconv.FormatUint(i, 10)+".cer", []byte(each), 0644)
				fmt.Println(each)
			}
		 }

		 if r.MatchString(string(buf)) {
			// scan for strings which look like base64, then verify that it is base64
			var str = strings.Replace(string(buf), "\n", "", -1)
			for _, each := range r.FindAllString(str,-1) {
			        _, err := base64.StdEncoding.DecodeString(each)
				if err == nil && len(each) > 10 {
					//fmt.Println(each)
				}
			}
		 }
         }
 }
