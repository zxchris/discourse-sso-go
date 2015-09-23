package static

import (
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

			b, err := config.Asset()("static" + path)
			if err != nil {
				panic(err)
			}

			mimeType := http.DetectContentType(b)

			log.Printf("using mime type %s\n", mimeType)

			r.Path(path).Methods("GET").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", mimeType)
				w.Header().Set("Cache-control", "public, max-age=259200")
				w.WriteHeader(200)
				w.Write(b)
			})
		}
	}
}
