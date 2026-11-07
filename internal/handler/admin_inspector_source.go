package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// handlerSource describes the Go function that served a request, so the
// inspector can show "which code handled this" next to the request details.
type handlerSource struct {
	Func string // short name, e.g. (*Handler).listEntries
	File string // file name inside internal/handler
	Line int
	Code string // source of the function; empty when the source is not on disk

	Middlewares []string
	ShowCode    bool // false when source display is disabled by config
}

// routeInfo is what the inspector knows about the code behind one route.
type routeInfo struct {
	Handler     string   // runtime name of the endpoint handler
	Middlewares []string // short names, outermost first
}

// buildRouteIndex maps "METHOD /route/pattern" to its handler and middleware chain.
func buildRouteIndex(r chi.Routes) map[string]routeInfo {
	idx := map[string]routeInfo{}
	_ = chi.Walk(r, func(method, route string, handler http.Handler, mws ...func(http.Handler) http.Handler) error {
		if handler == nil {
			return nil
		}
		info := routeInfo{Handler: funcName(handler)}
		for _, mw := range mws {
			info.Middlewares = append(info.Middlewares, shortFuncName(funcName(mw)))
		}
		idx[method+" "+route] = info
		return nil
	})
	return idx
}

func funcName(v any) string {
	if fn := runtime.FuncForPC(reflect.ValueOf(v).Pointer()); fn != nil {
		return fn.Name()
	}
	return ""
}

// shortFuncName turns "vsf/internal/handler.(*Handler).requireSession-fm"
// into "(*Handler).requireSession".
func shortFuncName(full string) string {
	short := full[strings.LastIndex(full, "/")+1:]
	short = strings.TrimSuffix(short, "-fm")
	return strings.TrimPrefix(short, "handler.")
}

var sourceCache sync.Map // method name -> *handlerSource (nil value cached too)

// lookupHandlerSource resolves a runtime function name such as
// "vsf/internal/handler.(*Handler).listEntries-fm" to its source. Source is
// read from the directory this file was compiled from, so it only works when
// the server runs next to the checkout (development); otherwise only the name
// is returned.
func lookupHandlerSource(fullName string) *handlerSource {
	if fullName == "" {
		return nil
	}

	cp := *lookupCached(fullName)
	return &cp
}

func lookupCached(fullName string) *handlerSource {
	short := shortFuncName(fullName)
	out := &handlerSource{Func: short, ShowCode: true}

	dot := strings.LastIndex(short, ".")
	method := short[dot+1:]
	if dot < 0 || strings.HasPrefix(method, "func") { // closure: no named declaration
		return out
	}

	if v, ok := sourceCache.Load(method); ok {
		if cached, _ := v.(*handlerSource); cached != nil {
			return cached
		}
		return out
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return out
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		sourceCache.Store(method, (*handlerSource)(nil))
		return out
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			continue
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != method {
				continue
			}
			start, end := fset.Position(fd.Pos()), fset.Position(fd.End())
			code := string(src[start.Offset:end.Offset])
			lines := strings.Split(code, "\n")
			if len(lines) > 80 {
				code = strings.Join(lines[:80], "\n") + "\n// ... (đã cắt bớt)"
			}
			res := &handlerSource{Func: short, File: e.Name(), Line: start.Line, Code: code, ShowCode: true}
			sourceCache.Store(method, res)
			return res
		}
	}

	sourceCache.Store(method, (*handlerSource)(nil))
	return out
}
