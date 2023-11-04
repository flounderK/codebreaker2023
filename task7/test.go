package main
import (
	"encoding/json"
	"fmt"
)

/*
type json.RawMessage struct {
    byte * __values;
    ulonglong __count;
    ulonglong __capacity;
};
*/

type CommandResponse struct {
    Id [16]byte
    Starttime string
    Endtime string
    Cmd string
    Stdout string
    Stderr string
    Err string
}


type StatusData struct {
    BalloonID [16]byte
    SystemInfo json.RawMessage
}

type StatusUpdate struct {
    StatusData StatusData
    CommandResponse * CommandResponse
}


//BalloonID: "ff61e7cd-4b5b-490d-8776-ad31f891f891",

func main() {

	supd := &StatusUpdate {
		StatusData: StatusData{
			BalloonID: [16]byte{0xff, 0x61, 0xe7, 0xcd, 0x4b, 0x5b, 0x49, 0x0d, 0x87, 0x76, 0xad, 0x31, 0xf8, 0x91, 0xf8, 0x91},
		},
		CommandResponse: &CommandResponse{
			Cmd: "ip a",
			Stdout: "",
			Stderr: "",
		},
	}
	supd_json, _ := json.Marshal(supd)
    //fmt.Println("hello world")
    fmt.Println(string(supd_json))
}
