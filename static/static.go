package static

import (
	"mime"
	"net/http"
	"strings"

	"github.com/gorilla/pat"
	"log"
)

type Config interface {
	Asset() func(string) ([]byte, error)
	AssetNames() func() []string
}

// Register creates routes for each static resource
func Register(config Config, r *pat.Router) {
	//log.Debug("registering not found handler for static package", nil)
	//r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
	//	render.HTML(w, http.StatusNotFound, "error", render.DefaultVars(req, map[string]interface{}{"error": "Page not found"}))
	//})

	log.Printf("registering static content handlers for static package\n")
	for _, file := range config.AssetNames()() {
		if strings.HasPrefix(file, "static/") {
			path := strings.TrimPrefix(file, "static")
			log.Printf("registering handler for static asset %s\n", path)

			var mimeType string
			switch {
			case strings.HasSuffix(path, ".css"):
				mimeType = "text/css"
			case strings.HasSuffix(path, ".js"):
				mimeType = "application/javascript"
			default:
				mimeType = mime.TypeByExtension(path) // Should rather use type-by-file-content or whatever it is......
			}

			log.Printf("using mime type %s\n", mimeType)

			r.Path(path).Methods("GET").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if b, err := config.Asset()("static" + path); err == nil {
					w.Header().Set("Content-Type", mimeType)
					w.Header().Set("Cache-control", "public, max-age=259200")
					w.WriteHeader(200)
					w.Write(b)
					return
				}
				// This should never happen!
				r.NotFoundHandler.ServeHTTP(w, req)
			})
		}
	}
}
