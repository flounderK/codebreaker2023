
package main
import (
//    "encoding/json"
    "fmt"
	"log"
	"net/http"
)


func blah_handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func main() {
    http.HandleFunc("/blah", blah_handler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}


