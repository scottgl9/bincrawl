// bincrawl written by Scott Glover 

package main

 import (
	 "encoding/binary"
	 "encoding/hex"
	 "bufio"
     "bytes"
	 "encoding/base64"
     "flag"
     "fmt"
     "io"
     "io/ioutil"
     "path/filepath"
	 "regexp"
     "math"
     "os"
     "strconv"
     "strings"
 )

const fileChunk = 8192

var inValue = flag.String("invalue", "", "Value to scan file for")
var inForm = flag.String("inform", "str", "Data format of invalue (b64, hex, str)")
var inFile = flag.String("infile", "", "file containing list of input values (b64, hex, or str)")
var fileToScan = flag.String("filename", "", "Name of file to scan.")
var scanPem = flag.Bool("scanpem", false, "Scan for PEM format cert in file")
var scanBase64 = flag.Bool("scanb64", false, "Scan for strings which match Base64 encoded requirements")
var scanDer = flag.Bool("scander", false, "Scan for DER format cert in file")

func scanFile(filename string) {
	strlist := []string{}
        //fmt.Printf("Scanning %s....\n", filename)
	if *inFile != "" {
		f, err := os.Open(*inFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer f.Close()
		r := bufio.NewReader(f)
		line, err := r.ReadString('\n')    // line defined once
		for err != io.EOF {
			line = strings.Replace(line, "\n", "", -1)
			strlist = append(strlist, line)
			line, err = r.ReadString('\n') //  line was defined before
		}
	}

	file, err := os.Open(filename)
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
	cnt:=0
	// we scan the file for Signature block by block
	for i := uint64(0); i < blocks; i++ {
		blocksize := int(math.Min(fileChunk, float64(filesize-int64(i*fileChunk))))
		buf := make([]byte, blocksize)
		//fmt.Printf("Scanning block #%d , size of %d\n", i, blocksize)
		file.Read(buf)

		if *inValue != "" {
			strlist = append(strlist, *inValue)
		}
		for _, strval := range strlist {
			if *inForm == "hex" {
				hexstr := strings.ToLower(strval)
				if bytes.Contains(buf, []byte(hexstr)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(hexstr))
					fmt.Printf("Found string form of hex %v in %v at offset %X\n", hexstr, filename, pos)
				}
				b64str := base64.StdEncoding.EncodeToString([]byte(hexstr))
				b64str = strings.Replace(b64str, "=", "", -1)
				if bytes.Contains(buf, []byte(b64str)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(b64str))
					fmt.Printf("Found base64 encoded hex form %v in %v at offset %X\n", b64str, filename, pos)
				}

				hexstr = strings.ToUpper(strval)
				if bytes.Contains(buf, []byte(hexstr)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(hexstr))
					fmt.Printf("Found string form of hex %v in %v at offset %X\n", hexstr, filename, pos)
				}
				b64str = base64.StdEncoding.EncodeToString([]byte(hexstr))
				b64str = strings.Replace(b64str, "=", "", -1)
				if bytes.Contains(buf, []byte(b64str)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(b64str))
					fmt.Printf("Found base64 encoded hex form %v in %v at offset %X\n", b64str, filename, pos)
				}

				data, _ := hex.DecodeString(strval)
				if bytes.Contains(buf, data) {
					pos := (int(i) * blocksize) + bytes.Index(buf, data);
					fmt.Printf("Found binary form of hex in %v at offset %X\n", filename, pos)
				}
				b64str = base64.StdEncoding.EncodeToString(data)
				b64str = strings.Replace(b64str, "=", "", -1)
				if bytes.Contains(buf, []byte(b64str)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(b64str))
					fmt.Printf("Found base64 encoded binary form %v in %v at offset %X\n", b64str, filename, pos)
				}
				// base64 encode it again, and see if we can find that
				b64str = base64.StdEncoding.EncodeToString([]byte(b64str))
				b64str = strings.Replace(b64str, "=", "", -1)
				if bytes.Contains(buf, []byte(b64str)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(b64str));
					fmt.Printf("Found double base64 encoded binary form %v in %v at offset %X\n", b64str, filename, pos)
				}
			} else if *inForm == "str" {
				hexstr := strings.ToLower(strval)
				if bytes.Contains(buf, []byte(hexstr)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(hexstr));
					fmt.Printf("Found string form of str %v in %v at offset %X\n", hexstr, filename, pos);
				}
				b64str := base64.StdEncoding.EncodeToString([]byte(hexstr))
				b64str = strings.Replace(b64str, "=", "", -1)
				if bytes.Contains(buf, []byte(b64str)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(b64str));
					fmt.Printf("Found base64 encoded str form %v in %v at offset %X\n", b64str, filename, pos)
				}

				hexstr = strings.ToUpper(strval)
				if bytes.Contains(buf, []byte(hexstr)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(hexstr));
					fmt.Printf("Found string form of str %v in %v at offset %X\n", hexstr, filename, pos);
				}
				b64str = base64.StdEncoding.EncodeToString([]byte(hexstr))
				b64str = strings.Replace(b64str, "=", "", -1)
				if bytes.Contains(buf, []byte(b64str)) {
					pos := (int(i) * blocksize) + bytes.Index(buf, []byte(b64str));
					fmt.Printf("Found base64 encoded str form %v in %v at offset %X\n", b64str, filename, pos)
				}
			}
		}

		if *scanDer && bytes.Contains(buf, []byte("\x30\x82")) {
			var length uint16
			tmpbuf := buf
			for {
				pos := bytes.Index(tmpbuf, []byte("\x30\x82"))
				if pos == -1 { break }
				if bytes.Equal(tmpbuf[pos+4:pos+6], []byte("\x30\x82")) {
					err := binary.Read(bytes.NewReader(tmpbuf[pos+2:pos+4]), binary.BigEndian, &length)
					if err != nil {
						fmt.Println("binary.Read failed:", err)
					}
					fmt.Printf("Found DER cert: %d\n", length)
					if (len(tmpbuf) <= pos+8+int(length)) {
						fmt.Printf("Cert spans block boundary\n")
					}
					//file.Seek(-len(buf), 1)

					if len(tmpbuf) > (pos+int(length)) {
						ioutil.WriteFile("data/"+strconv.FormatUint(uint64(cnt), 10)+".der", tmpbuf[pos:pos+int(length)], 0644)
					} else {
						// data is spanning two blocks
						//part1 := tmpbuf[pos:]
						//file.Read(buf)
						//part2 := buf[0:int(length) + 5 - len(part1)]
						//whole := append(part1, part2...)
						//ioutil.WriteFile("data/"+strconv.FormatUint(uint64(cnt), 10)+".der", whole, 0644)
					}
					cnt = cnt + 1
					if (len(tmpbuf) <= pos+8+int(length)) { break }
					tmpbuf = tmpbuf[pos+8:]
				} else {
					if (len(tmpbuf) <= pos+8) { break }
					tmpbuf = tmpbuf[pos+8:]
				}
			}
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

func scanDirectory(pathname string) {
	files, err := ioutil.ReadDir(pathname)
	if err != nil {
		fmt.Printf("Failed to read directory %v:\n%v", pathname, err.Error())
		return
	}

	for _, f := range files {

		path := filepath.Join(pathname, f.Name())

		stat, err := os.Stat(path)
		if err != nil {
			fmt.Printf("Failed to stat path %v:\n%v", path, err.Error())
			return
		}

		if stat.IsDir() {
			scanDirectory(path)
			continue
		}
		//fmt.Printf("%v\n", path)
		scanFile(path)
	}
}

func main() {
		flag.Parse()

		if (*fileToScan == "") {
			flag.PrintDefaults()
			os.Exit(0)
		}

		stat, err := os.Stat(*fileToScan)
		if err != nil {
			fmt.Printf("Failed to stat path %v:\n%v", *fileToScan, err.Error())
			os.Exit(-1)
		}
		if stat.IsDir() {
			scanDirectory(*fileToScan)
		} else {
			scanFile(*fileToScan)
		}
}
