// Package bestcookie implements the bestcookie algorithm
// and provides this to Golang's HTTP server.
//
// __Setup__
// > go get github.com/snadrus/bestcookie
//
// __Run as Part of Builds__
// go run bestcookie.go <mykeys.go >mykeys.go
// Only the global private "bestCookieKeys" gets replaced:
//   package mypkg
//   var bestCookieKeys = []bestcookie.Keys{}
//
// Use in code:
//
package bestcookie

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/gorilla/securecookie"
)

type BestCookie struct {
	name    string
	auth    *securecookie.SecureCookie
	olds    []*securecookie.SecureCookie
	timeout int
}

type Key struct {
	Month byte
	Year  uint16
	Key   string
}

const keysName = "bestCookieKeys"

// RotateKeys result should be shared with all servers.
// Call this at build time:
// go run bestcookie.go <mykeys.go >mykeys.go
// Only the global private "bestCookieKeys" gets replaced:
//   package mypkg
//   var bestCookieKeys = []bestcookie.Keys{}
//
func RotateKeys(keys *[]Key) {
	now := time.Now()
	sort.Slice(*keys, func(i, j int) bool {
		return int((*keys)[i].Year)<<int(8+(*keys)[i].Month) >
			int((*keys)[j].Year)<<int(8+(*keys)[j].Month)
	})
	if len(*keys) == 0 || byte(now.Month()) != (*keys)[0].Month || now.Year() != int((*keys)[0].Year) {
		b96 := make([]byte, 96)
		_, err := rand.Read(b96)
		if err != nil {
			panic("rand failed: " + err.Error())
		}

		newKey := Key{
			Month: byte(time.Now().Month()),
			Year:  uint16(time.Now().Year()),
			Key:   base64.StdEncoding.EncodeToString(b96),
		}

		if len(*keys) != 0 {
			*keys = []Key{newKey, (*keys)[0]}
		} else {
			*keys = []Key{newKey}
		}
	}
}

var rgx = regexp.MustCompile(`(\d+), (\d+), (.*)`)

func main() {
	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		os.Stderr.Write([]byte("io read error"))
		panic(1)
	}

	beginsWith := []byte("\nvar " + keysName + " = []bestcookie.Keys{")

	// Easy way
	idx := bytes.Index(b, beginsWith)
	idxEnd := len(b)
	keys := []Key{}
	if idx == -1 {
		idx = len(b)
		idxEnd = len(b)
	} else {
		remain := b[idx+len(beginsWith):]
		// find }, determine if { precedes it, read values
		// parse object. Ex:
		// {
		//    {12, 2006, "blablablablabla"},
		//    {11, 2006, "foofoofoofoofoo"},
		// }
		cl := bytes.IndexByte(remain, byte('}'))
		for {
			if cl == -1 {
				panic("malformed key area. Have {} match")
			}
			opn := bytes.IndexByte(remain[:cl], byte('{'))
			if opn == -1 {
				break
			}
			// remain[opn+1:cl] should look like {12, 2006, "bla"
			res := rgx.FindSubmatch(remain[opn+1 : cl])
			m, err1 := strconv.Atoi(string(res[1]))
			y, err2 := strconv.Atoi(string(res[2]))
			if err1 != nil || err2 != nil {
				panic("Couldn't locate month or year.")
			}
			keys = append(keys, Key{
				Month: byte(m),
				Year:  uint16(y),
				Key:   string(res[3][1:len(res[3])]),
			})
			remain = remain[cl+1:]
			idxEnd += cl + 1
		}

	}

	// rewrite orig file up to here.
	os.Stdout.Write(b[:idx])
	RotateKeys(&keys)
	fmt.Println(string(beginsWith) + " {")
	for _, k := range keys {
		fmt.Printf(`\t{%d, %d, "%s"},\n`, k.Month, k.Year, k.Key)
	}
	fmt.Println("}")
	os.Stdout.Write(b[idxEnd:])
	/*
	   	// HARD way??
	   	fset := token.NewFileSet()
	   	f, err := parser.ParseFile(fset, "", string(b), 0)
	   	if err != nil {
	   		fmt.Fprint(os.Stderr, "Error: "+err.Error())
	   		panic(1)
	   	}
	   	var putback func([]ast.Expr) []byte
	   	var bestCookieValueAST []ast.Expr
	   	for i, d := range f.Decls {
	   		genD, ok := d.(*ast.GenDecl)
	   		if !ok || genD.Tok != token.VAR {
	   			continue
	   		}
	   		for si, sI := range genD.Specs {
	   			s := sI.(*ast.ValueSpec)
	   			for ni, nI := range s.Names {
	   				if nI.Name == keysName {
	   					bestCookieValueAST = s.Values[ni].(*ast.CompositeLit).Elts
	   					putback = func(v []ast.Expr) []byte {
	   						f.Decls[i].(*ast.GenDecl).Specs[si].(*ast.ValueSpec).Values[ni].(*ast.CompositeLit).Elts = v
	   						b := bytes.NewBuffer(nil)
	   						if err := printer.Fprint(b, fset, f); err != nil {
	   							log.Fatal("Cannot write tree: " + err.Error())
	   						}
	   						return b.Bytes()
	   					}
	   					goto done
	   				}
	   			}
	   		}
	   	}
	   	// Not found case.
	   	v, _ := parser.ParseFile(token.NewFileSet(), "", []byte(string(beginsWith)+"{}"), 0)
	   	putback = func(v []ast.Expr) []byte {
	   		b:=bytes.NewBuffer(nil)
	   		if err := printer.Fprint(b, fset, f); err != nil {
	   			log.Fatal("cannot write tree: "+err.Error())
	   		}
	   		b.WriteBytes(beginsWith)
	   		elts := ""
	   		for _, item := range v {
	   			elts += fmt.Sprint(`{%d,%d,"%s"},\n`, item.)
	   		}
	   		b.WriteString("{\n " + elts + "}")
	   		return b.Bytes()
	   	}
	   	panic("file must have " + beginsWith)
	   done:
	   		// old to do change bestCookieValueAST
	*/
}

func getKeys(s string) (h []byte, b []byte) {
	// b96
	by, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return by[:64], by[64:]

}

func New(cookieName string, keys []Key, timeout time.Duration) *BestCookie {
	// set keys to keydata of those keys
	hashKey, blockKey := getKeys(keys[0].Key)

	auth := securecookie.New(hashKey, blockKey)
	auth.MaxAge(3600)
	auth.SetSerializer(securecookie.GobEncoder{})
	b := &BestCookie{
		name:    cookieName,
		auth:    auth,
		timeout: int(timeout.Seconds()),
	}
	auth.MaxAge(int(timeout.Seconds()))
	for _, v := range keys[1:] {
		hashKey, blockKey := getKeys(v.Key)
		auth := securecookie.New(hashKey, blockKey)
		auth.MaxAge(3600)
		auth.SetSerializer(securecookie.GobEncoder{})
		b.olds = append(b.olds, auth)
	}
	return b
}

func (b *BestCookie) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Our middleware logic goes here...

		c, err := r.Cookie(b.name)
		if err != nil {
			return
		}

		data := map[string]interface{}{}

		var workingDecoder = b.auth
		err = b.auth.Decode(b.name, c.Value, data)
		if err != nil {
			for _, auth := range b.olds {
				err = auth.Decode(b.name, c.Value, data)
				if err == nil {
					workingDecoder = auth
					goto done
				}
			}
			return
		done:
		}

		// always refresh
		b.UpdateCookieBytes(w, data)
		ctx := context.WithValue(r.Context(), "cookie-"+b.name, func(dst interface{}) error {
			return workingDecoder.Decode(b.name, c.Value, dst)
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (b *BestCookie) getCookie(r *http.Request, dst interface{}) error {
	c, err := r.Cookie(b.name)
	if err != nil {
		return err
	}

	err = b.auth.Decode(b.name, c.Value, dst)
	if err != nil {
		for _, auth := range b.olds {
			err = auth.Decode(b.name, c.Value, dst)
			if err == nil {
				goto done
			}
		}
		return err
	done:
	}
	return nil
}

// UpdateCookie adds or updates a cookie
func (b *BestCookie) UpdateCookieBytes(w http.ResponseWriter, msg interface{}) error {
	s, err := b.auth.Encode(b.name, msg)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     b.name,
		Value:    s,
		Path:     "/",
		MaxAge:   int(b.timeout),
		Domain:   "/",
		Secure:   true,
		HttpOnly: true,
	})
	return nil
}
