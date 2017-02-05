package authcode

import (
	"fmt"
	"github.com/skratchdot/open-golang/open"
)

func Open(s string) error {
	fmt.Println("opening", s)
	return open.StartWith(s, "Google Chrome")
}
