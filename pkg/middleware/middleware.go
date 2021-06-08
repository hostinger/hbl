package middleware

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
)

func KeyAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		key := c.Request().Header.Get("X-API-Key")
		if key == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Header X-API-Key missing in request")
		}
		if key != os.Getenv("HBL_API_TOKEN") {
			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized")
		}
		return next(c)
	}
}
