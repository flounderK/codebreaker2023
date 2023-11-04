
package main
import (
//    "encoding/json"
    "fmt"
	"os"
	"log"
	"golang.org/x/crypto/ssh"
)


//golang.org/x/crypto/ssh.ParseAuthorizedKey

func main() {
	arg := os.Args[1]

	key_bytes, err := os.ReadFile(arg)

	if err != nil {
		log.Fatal(err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(key_bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(pubKey.Marshal()))


}
