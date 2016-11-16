// bincrawl written by Scott Glover 

package main

 import (
//         "bytes"
         "fmt"
//         "io/ioutil"
	 "regexp"
         "math"
         "os"
         "strings"
 )

 const fileChunk = 8192

 var (
         startSignature = "-----BEGIN\x20CERTIFICATE"
         endSignature   = "END\x20CERTIFICATE-----"
 )

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

	 r, _ := regexp.Compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\\n")

         // we scan the file for Signature block by block
         for i := uint64(0); i < blocks; i++ {

                 blocksize := int(math.Min(fileChunk, float64(filesize-int64(i*fileChunk))))
                 buf := make([]byte, blocksize)

                 fmt.Printf("Scanning block #%d , size of %d\n", i, blocksize)

                 file.Read(buf)
		 if r.MatchString(string(buf)) {
			fmt.Println(r.FindAllString(string(buf),-1))
		 }
                 if strings.Contains(string(buf), string(startSignature)) {
                         //fmt.Println(string(buf))
                         fmt.Println("Found at block # : ", i)

                         // we want to find the out start and end positions of the signature
                         start := strings.Index(string(buf), startSignature)
                         end := strings.LastIndex(string(buf), endSignature)
                         foundSize := ((end - start) + len(endSignature))
                         fmt.Println("Detected size is : ", foundSize)

                         startPosition := (i * fileChunk) + uint64(start)
                         endPosition := startPosition + uint64(foundSize)
                         fmt.Println("Start position : ", startPosition)
                         fmt.Println("End position : ", endPosition)
                 }
         }
 }
