// MBDB
//
// Opens an Applle MBDB file created from iPhone backups
//
//	Work in progress
//
// https://www.theiphonewiki.com/wiki/ITunes_Backup#Manifest.mbdb
// https://code.google.com/archive/p/iphonebackupbrowser/wikis/MbdbMbdxFormat.wiki
// https://stackoverflow.com/questions/3085153/how-to-parse-the-manifest-mbdb-file-in-an-ios-4-0-itunes-backup
package mbdb

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pkg/errors"
)

const MBDBHeader = "mbdb\x05\x00"

// FileInfo
//
// string Domain
// string Path
// string LinkTarget absolute path
// string DataHash SHA.1 (some files only)
// string unknown always N/A
// uint16 Mode same as mbdx.Mode
// uint32 unknown always 0
// uint32 unknown
// uint32 UserId
// uint32 GroupId mostly 501 for apps
// uint32 Time1 relative to unix epoch (e.g time_t)
// uint32 Time2 Time1 or Time2 is the former ModificationTime
// uint32 Time3
// uint64 FileLength always 0 for link or directory
// uint8 Flag 0 if special (link, directory), otherwise unknown
// uint8 PropertyCount number of properties following
//
// string name string value can be a string or a binary content
type FileInfo struct {
	Domain                 string         `json:"domain"`
	Path                   string         `json:"path"`
	LinkTargetAbsolutePath string         `json:"link_target"`         // Absolute path
	DataHash               string         `json:"data_hash,omitempty"` // SHA-1 (some files only)
	EncryptionKey          string         `json:"encryption_key"`      // Always "N/A"
	Mode                   uint16         `json:"mode"`                // Same as mbdx.Mode
	InodeNumber            uint64         `json:"inode_number"`        // Always 0
	UserID                 uint32         `json:"user_id"`
	GroupID                uint32         `json:"group_id"` // Mostly 501 for apps
	LastModifiedTime       time.Time      `json:"time_1"`   // Relative to Unix epoch
	LastAccessedTime       time.Time      `json:"time_2"`   // ModificationTime (either Time1 or Time2)
	CreateTime             time.Time      `json:"time_3"`
	FileLength             uint64         `json:"file_length"` // Always 0 for link or directory
	Flag                   uint8          `json:"flag"`        // 0 if special (link, directory)
	Properties             []FileProperty `json:"properties"`
}

type FileProperty struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

// func (t FileProperty) DecodedValue() ([]byte, error) {
//	return base64.StdEncoding.DecodeString(t.Value)
// }

func (t FileInfo) Filename() string {
	h := sha1.New()
	io.WriteString(h, t.Domain)
	io.WriteString(h, "-")
	io.WriteString(h, t.Path)
	arr := h.Sum(nil)
	return hex.EncodeToString(arr)
}

func (t FileInfo) String() string {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

type Reader struct {
	reader io.ReadCloser
}

func NewFile(filename string) (*Reader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return NewReader(f)
}

func NewReader(reader io.ReadCloser) (*Reader, error) {
	if err := checkString(reader, MBDBHeader); err != nil {
		return nil, errors.Wrapf(err, "Not an MBDB files, incorrect file header")
	}

	return &Reader{
		reader: reader,
	}, nil
}

func (t *Reader) Close() error {
	return t.reader.Close()
}

func (t *Reader) ReadAll() ([]*FileInfo, error) {
	files := make([]*FileInfo, 0, 100)
	for {
		fi, err := t.Next()
		if err != nil {
			return nil, errors.Wrapf(err, "Error getting next record")
		}

		if fi == nil {
			break
		}

		files = append(files, fi)
	}
	return files, nil
}

func (t *Reader) Next() (*FileInfo, error) {
	fi, err := readFileInfo(t.reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "Error reading FileInfo record")
	}
	return fi, nil
}

func readFileInfo(r io.Reader) (*FileInfo, error) {
	domain, err := readString16(r)
	if err != nil {
		return nil, err
	}

	path, err := readString16(r)
	if err != nil {
		return nil, err
	}

	absPath, err := readString16(r)
	if err != nil {
		return nil, err
	}

	/*
		dataHash, err := readString16(r)
		if err != nil {
			return nil, err
		}
			fmt.Printf("h: [%s]\n", dataHash)
	*/

	dataHash, err := readBytes16(r)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("h: %x\n", hashBytes)
	// h := sha1.Sum(hashBytes)
	// dataHash := hex.EncodeToString(h[:])

	encryptionKey, err := readString16(r)
	if err != nil {
		return nil, err
	}

	mode, err := readUint16(r)
	if err != nil {
		return nil, err
	}

	inodeNumber, err := readUint64(r)
	if err != nil {
		return nil, err
	}

	userID, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	groupID, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	time1, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	time2, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	time3, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	fileLength, err := readUint64(r)
	if err != nil {
		return nil, err
	}

	flag, err := readUint8(r)
	if err != nil {
		return nil, err
	}

	propCount, err := readUint8(r)
	if err != nil {
		return nil, err
	}

	props := make([]FileProperty, 0, propCount)
	for i := 0; i < int(propCount); i++ {
		name, err := readString16(r)
		if err != nil {
			return nil, err
		}

		value, err := readBytes16(r)
		if err != nil {
			return nil, err
		}

		props = append(props, FileProperty{
			Name:  name,
			Value: value,
		})
	}

	fi := FileInfo{
		Domain:                 domain,
		Path:                   path,
		LinkTargetAbsolutePath: absPath,
		DataHash:               hex.EncodeToString(dataHash),
		EncryptionKey:          encryptionKey,
		Mode:                   mode,
		InodeNumber:            inodeNumber,
		UserID:                 userID,
		GroupID:                groupID,
		LastModifiedTime:       time.Unix(int64(time1), 0),
		LastAccessedTime:       time.Unix(int64(time2), 0),
		CreateTime:             time.Unix(int64(time3), 0),
		FileLength:             fileLength,
		Flag:                   flag,
		Properties:             props,
	}

	return &fi, nil
}

/*
func MBDBReader(filename string) ([]FileInfo, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	if err := checkString(f, MBDBHeader); err != nil {
		return nil, err
	}

	files := make([]FileInfo, 0, 100)
	for {
		fi, err := ReadFileInfo(f)
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println("eof")
				break
			}
			return nil, err
		}
		files = append(files, *fi)
	}

	return files, nil
}

func ReadFileInfo(r io.Reader) (*FileInfo, error) {
	domain, err := readString16(r)
	if err != nil {
		return nil, err
	}

	path, err := readString16(r)
	if err != nil {
		return nil, err
	}

	fmt.Println("P", path)

	absPath, err := readString16(r)
	if err != nil {
		return nil, err
	}

	//	dataHash, err := readString16(r)
	//	if err != nil {
	//		return nil, err
	//	}
	//	fmt.Printf("h: [%s]\n", dataHash)

	hashBytes, err := readBytes16(r)
	if err != nil {
		return nil, err
	}
	fmt.Printf("h: %x\n", hashBytes)

	h := sha1.Sum(hashBytes)
	dataHash := hex.EncodeToString(h[:])

	fmt.Println(dataHash)

	encryptionKey, err := readString16(r)
	if err != nil {
		return nil, err
	}

	mode, err := readUint16(r)
	if err != nil {
		return nil, err
	}

	inodeNumber, err := readUint64(r)
	if err != nil {
		return nil, err
	}

	userID, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	groupID, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	time1, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	time2, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	time3, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	fileLength, err := readUint64(r)
	if err != nil {
		return nil, err
	}

	flag, err := readUint8(r)
	if err != nil {
		return nil, err
	}

	propCount, err := readUint8(r)
	if err != nil {
		return nil, err
	}

	props := make([]FileProperty, 0, propCount)
	for i := 0; i < int(propCount); i++ {
		name, err := readString16(r)
		if err != nil {
			return nil, err
		}

		value, err := readBytes16(r)
		if err != nil {
			return nil, err
		}

		props = append(props, FileProperty{
			Name:  name,
			Value: value,
		})
	}

	fi := FileInfo{
		Domain:                 domain,
		Path:                   path,
		LinkTargetAbsolutePath: absPath,
		DataHash:               dataHash,
		EncryptionKey:          encryptionKey,
		Mode:                   mode,
		InodeNumber:            inodeNumber,
		UserID:                 userID,
		GroupID:                groupID,
		LastModifiedTime:       time.Unix(int64(time1), 0),
		LastAccessedTime:       time.Unix(int64(time2), 0),
		CreateTime:             time.Unix(int64(time3), 0),
		FileLength:             fileLength,
		Flag:                   flag,
		Properties:             props,
	}

	return &fi, nil
}
*/

func checkString(r io.Reader, str string) error {
	s, err := readString(r, len(str))
	if err != nil {
		return err
	}

	if s != str {
		return fmt.Errorf("str don't match [%s] [%s]", s, str)
	}

	return nil
}

func readString(r io.Reader, l int) (string, error) {
	str := make([]byte, l)
	if _, err := r.Read(str); err != nil {
		return "", err
	}
	return string(str), nil

}

func readString16(r io.Reader) (string, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}

	if length == 0xFFFF {
		return "", nil
	}

	str := make([]byte, length)
	if _, err := r.Read(str); err != nil {
		return "", err
	}
	return string(str), nil
}

func readBytes16(r io.Reader) ([]byte, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	if length == 0xFFFF {
		return nil, nil
	}

	b := make([]byte, length)
	if _, err := r.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func readUint8(r io.Reader) (uint8, error) {
	var i uint8
	if err := binary.Read(r, binary.BigEndian, &i); err != nil {
		return 0, err
	}
	return i, nil
}

func readUint16(r io.Reader) (uint16, error) {
	var i uint16
	if err := binary.Read(r, binary.BigEndian, &i); err != nil {
		return 0, err
	}
	return i, nil
}

func readUint32(r io.Reader) (uint32, error) {
	var i uint32
	if err := binary.Read(r, binary.BigEndian, &i); err != nil {
		return 0, err
	}
	return i, nil
}

func readUint64(r io.Reader) (uint64, error) {
	var i uint64
	if err := binary.Read(r, binary.BigEndian, &i); err != nil {
		return 0, err
	}
	return i, nil
}
