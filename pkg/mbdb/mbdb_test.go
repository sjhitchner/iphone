package mbdb

import (
	"bytes"
	"fmt"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type MBDBSuite struct{}

var _ = Suite(&MBDBSuite{})

const ManifestDB = "/Users/sjh/Library/Application Support/MobileSync/Backup/fd414c8df556b4d106f37c86899494793d3d012d/Manifest.mbdb"

func (s *MBDBSuite) Test_Reader(c *C) {
	reader, err := NewFile(ManifestDB)
	c.Assert(err, IsNil)
	defer reader.Close()

	records, err := reader.ReadAll()
	c.Assert(err, IsNil)
	c.Assert(len(records), Equals, 11156)
}

func (s *MBDBSuite) Test_Next(c *C) {
	reader, err := NewFile(ManifestDB)
	c.Assert(err, IsNil)
	defer reader.Close()

	var count int
	for {
		fi, err := reader.Next()
		c.Assert(err, IsNil)

		if fi == nil {
			break
		}

		fmt.Println(fi.Path, ",", fi.Filename())
		// if len(fi.Properties) > 0 {
		//	fmt.Println(fi)
		// }

		count++
	}

	c.Assert(count, Equals, 11156)
}

var sampleFileInfo = []byte{
	0x00, 0x0a, 0x48, 0x6f, 0x6d, 0x65, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
	0x00, 0x12, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x53, 0x4d,
	0x53, 0x2f, 0x73, 0x6d, 0x73, 0x2e, 0x64, 0x62, 0xff, 0xff, 0x00, 0x14,
	0xba, 0xbe, 0x12, 0x0f, 0x4d, 0xd7, 0x62, 0xb8, 0x5e, 0x91, 0xf1, 0xb3,
	0x3f, 0x9e, 0x4a, 0xc2, 0x13, 0x55, 0xa8, 0x9f, 0xff, 0xff, 0x81, 0xa4,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x01, 0xf5,
	0x00, 0x00, 0x01, 0xf5, 0x67, 0xd8, 0x75, 0x9e, 0x5a, 0x5e, 0xec, 0x90,
	0x51, 0x40, 0x2b, 0x26, 0x00, 0x00, 0x00, 0x00, 0x04, 0x56, 0x90, 0x00,
	0x03, 0x00,
}

func (s *MBDBSuite) Test_readFileInfo(c *C) {
	reader := bytes.NewReader(sampleFileInfo)

	fi, err := readFileInfo(reader)
	c.Assert(err, IsNil)

	// fmt.Println(fi, fi.Filename())

	c.Assert(fi.Domain, Equals, "HomeDomain")
	c.Assert(fi.Path, Equals, "Library/SMS/sms.db")
	c.Assert(fi.Filename(), Equals, "3d0d7e5fb2ce288813306e4d4636395e047a3d28")
	c.Assert(fi.FileLength, Equals, uint64(72781824))
}

func (s *MBDBSuite) Test_readFileInfoProperties(c *C) {
	reader := bytes.NewReader(sampleFileInfoWithProperties)

	fi, err := readFileInfo(reader)
	c.Assert(err, IsNil)

	// fmt.Println(fi, fi.Filename())

	c.Assert(fi.Domain, Equals, "MediaDomain")
	c.Assert(fi.Path, Equals, "Library/SMS/Attachments/00/00/03C1761F-22B2-4AF5-8811-E7D27DA1D95B/IMG_0607.JPG")
	c.Assert(fi.Filename(), Equals, "58c1c37348ef62b36c4fb6ff895d7bfc2beea259")
	c.Assert(fi.FileLength, Equals, uint64(2521549))
	c.Assert(len(fi.Properties), Equals, 11)
}

/*
while offset < len(data):
        fileinfo = {}
        fileinfo['start_offset'] = offset
        fileinfo['domain'], offset = getstring(data, offset)
        fileinfo['filename'], offset = getstring(data, offset)
        fileinfo['linktarget'], offset = getstring(data, offset)
        fileinfo['datahash'], offset = getstring(data, offset)
        fileinfo['unknown1'], offset = getstring(data, offset)
        fileinfo['mode'], offset = getint(data, offset, 2)
        fileinfo['unknown2'], offset = getint(data, offset, 4)
        fileinfo['unknown3'], offset = getint(data, offset, 4)
        fileinfo['userid'], offset = getint(data, offset, 4)
        fileinfo['groupid'], offset = getint(data, offset, 4)
        fileinfo['mtime'], offset = getint(data, offset, 4)
        fileinfo['atime'], offset = getint(data, offset, 4)
        fileinfo['ctime'], offset = getint(data, offset, 4)
        fileinfo['filelen'], offset = getint(data, offset, 8)
        fileinfo['flag'], offset = getint(data, offset, 1)
        fileinfo['numprops'], offset = getint(data, offset, 1)
fileinfo['properties'] = {}
        for ii in range(fileinfo['numprops']):
propname, offset = getstring(data, offset)
            propval, offset = getstring(data, offset)
            fileinfo['properties'][propname] = propval
        mbdb[fileinfo['start_offset']] = fileinfo

*/

/*
0020b5f0  00 0b 4d 65 64 69 61 44  6f 6d 61 69 6e 00 4f 4c  |..MediaDomain.OL|
0020b600  69 62 72 61 72 79 2f 53  4d 53 2f 41 74 74 61 63  |ibrary/SMS/Attac|
0020b610  68 6d 65 6e 74 73 2f 30  30 2f 30 30 2f 30 33 43  |hments/00/00/03C|
0020b620  31 37 36 31 46 2d 32 32  42 32 2d 34 41 46 35 2d  |1761F-22B2-4AF5-|
0020b630  38 38 31 31 2d 45 37 44  32 37 44 41 31 44 39 35  |8811-E7D27DA1D95|
0020b640  42 2f 49 4d 47 5f 30 36  30 37 2e 4a 50 47 ff ff  |B/IMG_0607.JPG..|
0020b650  ff ff ff ff 81 a4 00 00  00 00 01 02 b1 5d 00 00  |.............]..|
0020b660  01 f5 00 00 01 f5 56 31  9c 00 58 0d 9b 65 56 31  |......V1..X..eV1|
0020b670  9b ff 00 00 00 00 00 26  79 cd 03 0b 00 18 63 6f  |.......&y.....co|
0020b680  6d 2e 61 70 70 6c 65 2e  61 73 73 65 74 73 64 2e  |m.apple.assetsd.|
0020b690  68 69 64 64 65 6e 00 02  00 00 00 24 63 6f 6d 2e  |hidden.....$com.|
0020b6a0  61 70 70 6c 65 2e 61 73  73 65 74 73 64 2e 63 75  |apple.assetsd.cu|
0020b6b0  73 74 6f 6d 43 72 65 61  74 69 6f 6e 44 61 74 65  |stomCreationDate|
0020b6c0  00 32 62 70 6c 69 73 74  30 30 33 41 bb e1 d3 7f  |.2bplist003A....|
0020b6d0  d6 c8 b4 08 00 00 00 00  00 00 01 01 00 00 00 00  |................|
0020b6e0  00 00 00 01 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0020b6f0  00 00 00 11 00 16 63 6f  6d 2e 61 70 70 6c 65 2e  |......com.apple.|
0020b700  61 73 73 65 74 73 64 2e  55 55 49 44 00 10 05 63  |assetsd.UUID...c|
0020b710  d9 3a 3f 1c 4d e5 a8 ea  3d ce 55 c7 ed 69 00 1b  |.:?.M...=.U..i..|
0020b720  63 6f 6d 2e 61 70 70 6c  65 2e 61 73 73 65 74 73  |com.apple.assets|
0020b730  64 2e 61 73 73 65 74 54  79 70 65 00 02 03 00 00  |d.assetType.....|
0020b740  25 63 6f 6d 2e 61 70 70  6c 65 2e 61 73 73 65 74  |%com.apple.asset|
0020b750  73 64 2e 64 62 52 65 62  75 69 6c 64 49 6e 50 72  |sd.dbRebuildInPr|
0020b760  6f 67 72 65 73 73 00 02  00 00 00 20 63 6f 6d 2e  |ogress..... com.|
0020b770  61 70 70 6c 65 2e 61 73  73 65 74 73 64 2e 61 76  |apple.assetsd.av|
0020b780  61 6c 61 6e 63 68 65 2e  74 79 70 65 00 02 00 00  |alanche.type....|
0020b790  00 19 63 6f 6d 2e 61 70  70 6c 65 2e 61 73 73 65  |..com.apple.asse|
0020b7a0  74 73 64 2e 74 72 61 73  68 65 64 00 02 00 00 00  |tsd.trashed.....|
0020b7b0  1f 63 6f 6d 2e 61 70 70  6c 65 2e 61 73 73 65 74  |.com.apple.asset|
0020b7c0  73 64 2e 64 62 52 65 62  75 69 6c 64 55 75 69 64  |sd.dbRebuildUuid|
0020b7d0  00 24 31 36 31 44 30 35  43 39 2d 44 30 31 45 2d  |.$161D05C9-D01E-|
0020b7e0  34 43 39 34 2d 39 44 44  32 2d 44 44 39 41 42 45  |4C94-9DD2-DD9ABE|
0020b7f0  35 37 43 38 37 46 00 1a  63 6f 6d 2e 61 70 70 6c  |57C87F..com.appl|
0020b800  65 2e 61 73 73 65 74 73  64 2e 66 61 76 6f 72 69  |e.assetsd.favori|
0020b810  74 65 00 02 00 00 00 1b  63 6f 6d 2e 61 70 70 6c  |te......com.appl|
0020b820  65 2e 61 73 73 65 74 73  64 2e 61 64 64 65 64 44  |e.assetsd.addedD|
0020b830  61 74 65 00 32 62 70 6c  69 73 74 30 30 33 41 bb  |ate.2bplist003A.|
0020b840  e1 d3 80 79 ef 85 08 00  00 00 00 00 00 01 01 00  |...y............|
0020b850  00 00 00 00 00 00 01 00  00 00 00 00 00 00 00 00  |................|
0020b860  00 00 00 00 00 00 11 00  20 63 6f 6d 2e 61 70 70  |........ com.app|
0020b870  6c 65 2e 61 73 73 65 74  73 64 2e 63 75 73 74 6f  |le.assetsd.custo|
0020b880  6d 4c 6f 63 61 74 69 6f  6e 03 23 62 70 6c 69 73  |mLocation.#bplis|
0020b890  74 30 30 d4 01 02 03 04  05 08 2c 2d 54 24 74 6f  |t00.......,-T$to|
0020b8a0  70 58 24 6f 62 6a 65 63  74 73 58 24 76 65 72 73  |pX$objectsX$vers|
0020b8b0  69 6f 6e 59 24 61 72 63  68 69 76 65 72 d1 06 07  |ionY$archiver...|
0020b8c0  54 72 6f 6f 74 80 01 a3  09 0a 25 55 24 6e 75 6c  |Troot.....%U$nul|
0020b8d0  6c dd 0b 0c 0d 0e 0f 10  11 12 13 14 15 16 17 18  |l...............|
0020b8e0  19 1a 1b 1c 1d 1e 1f 20  21 22 23 24 5f 10 26 6b  |....... !"#$_.&k|
0020b8f0  43 4c 4c 6f 63 61 74 69  6f 6e 43 6f 64 69 6e 67  |CLLocationCoding|
0020b900  4b 65 79 43 6f 6f 72 64  69 6e 61 74 65 4c 61 74  |KeyCoordinateLat|
0020b910  69 74 75 64 65 5f 10 24  6b 43 4c 4c 6f 63 61 74  |itude_.$kCLLocat|
0020b920  69 6f 6e 43 6f 64 69 6e  67 4b 65 79 56 65 72 74  |ionCodingKeyVert|
0020b930  69 63 61 6c 41 63 63 75  72 61 63 79 5f 10 1d 6b  |icalAccuracy_..k|
0020b940  43 4c 4c 6f 63 61 74 69  6f 6e 43 6f 64 69 6e 67  |CLLocationCoding|
0020b950  4b 65 79 54 69 6d 65 73  74 61 6d 70 5f 10 26 6b  |KeyTimestamp_.&k|
0020b960  43 4c 4c 6f 63 61 74 69  6f 6e 43 6f 64 69 6e 67  |CLLocationCoding|
0020b970  4b 65 79 48 6f 72 69 7a  6f 6e 74 61 6c 41 63 63  |KeyHorizontalAcc|
0020b980  75 72 61 63 79 5f 10 1d  6b 43 4c 4c 6f 63 61 74  |uracy_..kCLLocat|
0020b990  69 6f 6e 43 6f 64 69 6e  67 4b 65 79 4d 61 74 63  |ionCodingKeyMatc|
0020b9a0  68 49 6e 66 6f 5f 10 1c  6b 43 4c 4c 6f 63 61 74  |hInfo_..kCLLocat|
0020b9b0  69 6f 6e 43 6f 64 69 6e  67 4b 65 79 4c 69 66 65  |ionCodingKeyLife|
0020b9c0  73 70 61 6e 5f 10 1a 6b  43 4c 4c 6f 63 61 74 69  |span_..kCLLocati|
0020b9d0  6f 6e 43 6f 64 69 6e 67  4b 65 79 43 6f 75 72 73  |onCodingKeyCours|
0020b9e0  65 5f 10 27 6b 43 4c 4c  6f 63 61 74 69 6f 6e 43  |e_.'kCLLocationC|
0020b9f0  6f 64 69 6e 67 4b 65 79  43 6f 6f 72 64 69 6e 61  |odingKeyCoordina|
0020ba00  74 65 4c 6f 6e 67 69 74  75 64 65 5f 10 1c 6b 43  |teLongitude_..kC|
0020ba10  4c 4c 6f 63 61 74 69 6f  6e 43 6f 64 69 6e 67 4b  |LLocationCodingK|
0020ba20  65 79 41 6c 74 69 74 75  64 65 5f 10 19 6b 43 4c  |eyAltitude_..kCL|
0020ba30  4c 6f 63 61 74 69 6f 6e  43 6f 64 69 6e 67 4b 65  |LocationCodingKe|
0020ba40  79 53 70 65 65 64 56 24  63 6c 61 73 73 5f 10 18  |ySpeedV$class_..|
0020ba50  6b 43 4c 4c 6f 63 61 74  69 6f 6e 43 6f 64 69 6e  |kCLLocationCodin|
0020ba60  67 4b 65 79 54 79 70 65  5f 10 19 6b 43 4c 4c 6f  |gKeyType_..kCLLo|
0020ba70  63 61 74 69 6f 6e 43 6f  64 69 6e 67 4b 65 79 46  |cationCodingKeyF|
0020ba80  6c 6f 6f 72 23 40 42 e0  eb c4 08 d8 ed 23 00 00  |loor#@B......#..|
0020ba90  00 00 00 00 00 00 23 00  00 00 00 00 00 00 00 23  |......#........#|
0020baa0  00 00 00 00 00 00 00 00  80 00 23 bf f0 00 00 00  |..........#.....|
0020bab0  00 00 00 23 00 00 00 00  00 00 00 00 23 c0 5e 9c  |...#........#.^.|
0020bac0  02 bb 0c f8 7e 23 40 16  6f df ee 82 18 6a 23 00  |....~#@.o....j#.|
0020bad0  00 00 00 00 00 00 00 80  02 10 00 12 7f ff ff ff  |................|
0020bae0  d2 26 27 28 2b 58 24 63  6c 61 73 73 65 73 5a 24  |.&'(+X$classesZ$|
0020baf0  63 6c 61 73 73 6e 61 6d  65 a2 29 2a 5a 43 4c 4c  |classname.)*ZCLL|
0020bb00  6f 63 61 74 69 6f 6e 58  4e 53 4f 62 6a 65 63 74  |ocationXNSObject|
0020bb10  5a 43 4c 4c 6f 63 61 74  69 6f 6e 12 00 01 86 a0  |ZCLLocation.....|
0020bb20  5f 10 0f 4e 53 4b 65 79  65 64 41 72 63 68 69 76  |_..NSKeyedArchiv|
0020bb30  65 72 00 08 00 11 00 16  00 1f 00 28 00 32 00 35  |er.........(.2.5|
0020bb40  00 3a 00 3c 00 40 00 46  00 61 00 8a 00 b1 00 d1  |.:.<.@.F.a......|
0020bb50  00 fa 01 1a 01 39 01 56  01 80 01 9f 01 bb 01 c2  |.....9.V........|
0020bb60  01 dd 01 f9 02 02 02 0b  02 14 02 1d 02 1f 02 28  |...............(|
0020bb70  02 31 02 3a 02 43 02 4c  02 4e 02 50 02 55 02 5a  |.1.:.C.L.N.P.U.Z|
0020bb80  02 63 02 6e 02 71 02 7c  02 85 02 90 02 95 00 00  |.c.n.q.|........|
0020bb90  00 00 00 00 02 01 00 00  00 00 00 00 00 2e 00 00  |................|
0020bba0  00 00 00 00 00 00 00 00  00 00 00 00 02 a7
*/

var sampleFileInfoWithProperties = []byte{
	0x00, 0x0b, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x4f, 0x4c,
	0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x53, 0x4d, 0x53, 0x2f, 0x41, 0x74, 0x74, 0x61, 0x63,
	0x68, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x2f, 0x30, 0x30, 0x2f, 0x30, 0x30, 0x2f, 0x30, 0x33, 0x43,
	0x31, 0x37, 0x36, 0x31, 0x46, 0x2d, 0x32, 0x32, 0x42, 0x32, 0x2d, 0x34, 0x41, 0x46, 0x35, 0x2d,
	0x38, 0x38, 0x31, 0x31, 0x2d, 0x45, 0x37, 0x44, 0x32, 0x37, 0x44, 0x41, 0x31, 0x44, 0x39, 0x35,
	0x42, 0x2f, 0x49, 0x4d, 0x47, 0x5f, 0x30, 0x36, 0x30, 0x37, 0x2e, 0x4a, 0x50, 0x47, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x81, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0xb1, 0x5d, 0x00, 0x00,
	0x01, 0xf5, 0x00, 0x00, 0x01, 0xf5, 0x56, 0x31, 0x9c, 0x00, 0x58, 0x0d, 0x9b, 0x65, 0x56, 0x31,
	0x9b, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x79, 0xcd, 0x03, 0x0b, 0x00, 0x18, 0x63, 0x6f,
	0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x64, 0x2e,
	0x68, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x24, 0x63, 0x6f, 0x6d, 0x2e,
	0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x64, 0x2e, 0x63, 0x75,
	0x73, 0x74, 0x6f, 0x6d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x65,
	0x00, 0x32, 0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0x33, 0x41, 0xbb, 0xe1, 0xd3, 0x7f,
	0xd6, 0xc8, 0xb4, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x11, 0x00, 0x16, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e,
	0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x64, 0x2e, 0x55, 0x55, 0x49, 0x44, 0x00, 0x10, 0x05, 0x63,
	0xd9, 0x3a, 0x3f, 0x1c, 0x4d, 0xe5, 0xa8, 0xea, 0x3d, 0xce, 0x55, 0xc7, 0xed, 0x69, 0x00, 0x1b,
	0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73,
	0x64, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x00, 0x02, 0x03, 0x00, 0x00,
	0x25, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74,
	0x73, 0x64, 0x2e, 0x64, 0x62, 0x52, 0x65, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x50, 0x72,
	0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x63, 0x6f, 0x6d, 0x2e,
	0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x64, 0x2e, 0x61, 0x76,
	0x61, 0x6c, 0x61, 0x6e, 0x63, 0x68, 0x65, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x19, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65,
	0x74, 0x73, 0x64, 0x2e, 0x74, 0x72, 0x61, 0x73, 0x68, 0x65, 0x64, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x1f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74,
	0x73, 0x64, 0x2e, 0x64, 0x62, 0x52, 0x65, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x55, 0x75, 0x69, 0x64,
	0x00, 0x24, 0x31, 0x36, 0x31, 0x44, 0x30, 0x35, 0x43, 0x39, 0x2d, 0x44, 0x30, 0x31, 0x45, 0x2d,
	0x34, 0x43, 0x39, 0x34, 0x2d, 0x39, 0x44, 0x44, 0x32, 0x2d, 0x44, 0x44, 0x39, 0x41, 0x42, 0x45,
	0x35, 0x37, 0x43, 0x38, 0x37, 0x46, 0x00, 0x1a, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c,
	0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x64, 0x2e, 0x66, 0x61, 0x76, 0x6f, 0x72, 0x69,
	0x74, 0x65, 0x00, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c,
	0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x64, 0x2e, 0x61, 0x64, 0x64, 0x65, 0x64, 0x44,
	0x61, 0x74, 0x65, 0x00, 0x32, 0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0x33, 0x41, 0xbb,
	0xe1, 0xd3, 0x80, 0x79, 0xef, 0x85, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x20, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70,
	0x6c, 0x65, 0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x73, 0x64, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f,
	0x6d, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x23, 0x62, 0x70, 0x6c, 0x69, 0x73,
	0x74, 0x30, 0x30, 0xd4, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x2c, 0x2d, 0x54, 0x24, 0x74, 0x6f,
	0x70, 0x58, 0x24, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x58, 0x24, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x59, 0x24, 0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x72, 0xd1, 0x06, 0x07,
	0x54, 0x72, 0x6f, 0x6f, 0x74, 0x80, 0x01, 0xa3, 0x09, 0x0a, 0x25, 0x55, 0x24, 0x6e, 0x75, 0x6c,
	0x6c, 0xdd, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x5f, 0x10, 0x26, 0x6b,
	0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67,
	0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x4c, 0x61, 0x74,
	0x69, 0x74, 0x75, 0x64, 0x65, 0x5f, 0x10, 0x24, 0x6b, 0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x74,
	0x69, 0x63, 0x61, 0x6c, 0x41, 0x63, 0x63, 0x75, 0x72, 0x61, 0x63, 0x79, 0x5f, 0x10, 0x1d, 0x6b,
	0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67,
	0x4b, 0x65, 0x79, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x5f, 0x10, 0x26, 0x6b,
	0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67,
	0x4b, 0x65, 0x79, 0x48, 0x6f, 0x72, 0x69, 0x7a, 0x6f, 0x6e, 0x74, 0x61, 0x6c, 0x41, 0x63, 0x63,
	0x75, 0x72, 0x61, 0x63, 0x79, 0x5f, 0x10, 0x1d, 0x6b, 0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x63,
	0x68, 0x49, 0x6e, 0x66, 0x6f, 0x5f, 0x10, 0x1c, 0x6b, 0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x4c, 0x69, 0x66, 0x65,
	0x73, 0x70, 0x61, 0x6e, 0x5f, 0x10, 0x1a, 0x6b, 0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x75, 0x72, 0x73,
	0x65, 0x5f, 0x10, 0x27, 0x6b, 0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43,
	0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x61,
	0x74, 0x65, 0x4c, 0x6f, 0x6e, 0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x5f, 0x10, 0x1c, 0x6b, 0x43,
	0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b,
	0x65, 0x79, 0x41, 0x6c, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x5f, 0x10, 0x19, 0x6b, 0x43, 0x4c,
	0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b, 0x65,
	0x79, 0x53, 0x70, 0x65, 0x65, 0x64, 0x56, 0x24, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x5f, 0x10, 0x18,
	0x6b, 0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e,
	0x67, 0x4b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x5f, 0x10, 0x19, 0x6b, 0x43, 0x4c, 0x4c, 0x6f,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x46,
	0x6c, 0x6f, 0x6f, 0x72, 0x23, 0x40, 0x42, 0xe0, 0xeb, 0xc4, 0x08, 0xd8, 0xed, 0x23, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x23, 0xbf, 0xf0, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0xc0, 0x5e, 0x9c,
	0x02, 0xbb, 0x0c, 0xf8, 0x7e, 0x23, 0x40, 0x16, 0x6f, 0xdf, 0xee, 0x82, 0x18, 0x6a, 0x23, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x10, 0x00, 0x12, 0x7f, 0xff, 0xff, 0xff,
	0xd2, 0x26, 0x27, 0x28, 0x2b, 0x58, 0x24, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x65, 0x73, 0x5a, 0x24,
	0x63, 0x6c, 0x61, 0x73, 0x73, 0x6e, 0x61, 0x6d, 0x65, 0xa2, 0x29, 0x2a, 0x5a, 0x43, 0x4c, 0x4c,
	0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x58, 0x4e, 0x53, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x5a, 0x43, 0x4c, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x00, 0x01, 0x86, 0xa0,
	0x5f, 0x10, 0x0f, 0x4e, 0x53, 0x4b, 0x65, 0x79, 0x65, 0x64, 0x41, 0x72, 0x63, 0x68, 0x69, 0x76,
	0x65, 0x72, 0x00, 0x08, 0x00, 0x11, 0x00, 0x16, 0x00, 0x1f, 0x00, 0x28, 0x00, 0x32, 0x00, 0x35,
	0x00, 0x3a, 0x00, 0x3c, 0x00, 0x40, 0x00, 0x46, 0x00, 0x61, 0x00, 0x8a, 0x00, 0xb1, 0x00, 0xd1,
	0x00, 0xfa, 0x01, 0x1a, 0x01, 0x39, 0x01, 0x56, 0x01, 0x80, 0x01, 0x9f, 0x01, 0xbb, 0x01, 0xc2,
	0x01, 0xdd, 0x01, 0xf9, 0x02, 0x02, 0x02, 0x0b, 0x02, 0x14, 0x02, 0x1d, 0x02, 0x1f, 0x02, 0x28,
	0x02, 0x31, 0x02, 0x3a, 0x02, 0x43, 0x02, 0x4c, 0x02, 0x4e, 0x02, 0x50, 0x02, 0x55, 0x02, 0x5a,
	0x02, 0x63, 0x02, 0x6e, 0x02, 0x71, 0x02, 0x7c, 0x02, 0x85, 0x02, 0x90, 0x02, 0x95, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xa7,
}
