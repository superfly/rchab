package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/superfly/flyctl/api"
)

func authRequest(next http.Handler) http.Handler {
	if noAuth {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appName, authToken, ok := r.BasicAuth()

		if !ok || !authorizeRequestWithCache(r.Context(), appName, authToken) {
			w.WriteHeader(http.StatusUnauthorized)
			err := json.NewEncoder(w).Encode(map[string]string{
				"message": "You are not authorized to use this builder",
			})
			if err != nil {
				log.Warnln("error writing response", err)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authorizeRequestWithCache(ctx context.Context, appName, authToken string) bool {
	if noAuth {
		return true
	}

	if appName == "" || authToken == "" {
		return false
	}

	cacheKey := appName + ":" + authToken
	if val, ok := authCache.Get(cacheKey); ok {
		if authorized, ok := val.(bool); ok {
			log.Debugln("authorized from cache")
			return authorized
		}
	}

	authorized := authorizeRequest(ctx, appName, authToken)
	authCache.Set(cacheKey, authorized, 0)
	log.Debugln("authorized from api")
	return authorized
}

// TODO: If we know that we're always going to use 6pn to access builders, we can probably just drop this auth since the network will take care to authorize access within the same org?
func authorizeRequest(ctx context.Context, appName, authToken string) bool {
	fly := api.NewClient(authToken, fmt.Sprintf("superfly/rchab/%s", gitSha), "0.0.0.0.0.0.1", log)

	app, err := fly.GetAppCompact(ctx, appName)
	if app == nil || err != nil {
		log.Warnf("Error fetching app %s: %v", appName, err)
		return false
	}

	// local dev only: we started machine with NO_APP_NAME=1, skip checking that appName from auth is in same org as this builder
	if noAppName {
		log.Warnf("Skipping organization check for app %s on builder", appName)
		return true
	}

	builderAppName, ok := os.LookupEnv("FLY_APP_NAME")
	if !ok {
		log.Warn("FLY_APP_NAME env var is not set!")
		return false
	}
	builderApp, err := fly.GetAppCompact(context.TODO(), builderAppName)
	if builderApp == nil || err != nil {
		log.Warnf("Error fetching builder app %s", builderAppName)
		return false
	}
	if app.Organization.ID != builderApp.Organization.ID {
		log.Warnf("App %s is in %s org, and builder %s is in %s org", appName, app.Organization.Slug, builderAppName, builderApp.Organization.Slug)
		return false
	}

	appOrg, err := fly.GetOrganizationBySlug(context.TODO(), app.Organization.Slug)
	if appOrg == nil || err != nil {
		log.Warnf("Error fetching org %s: %v", app.Organization.Slug, err)
		return false
	}
	builderOrg, err := fly.GetOrganizationBySlug(context.TODO(), builderApp.Organization.Slug)
	if builderOrg == nil || err != nil {
		log.Warnf("Error fetching org %s: %v", builderApp.Organization.Slug, err)
		return false
	}

	if app.Organization.ID != builderApp.Organization.ID {
		log.Warnf("App %s does not belong to org %s (builder app: '%s' builder org: '%s')", app.Name, appOrg.Slug, builderAppName, builderOrg.Slug)
		return false
	}

	return true
}
