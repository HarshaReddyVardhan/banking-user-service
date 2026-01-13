package validator

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

// CustomValidator wraps the playground validator
type CustomValidator struct {
	validator *validator.Validate
}

// New creates a new custom validator
func New() *CustomValidator {
	v := validator.New()

	// Register custom validations
	_ = v.RegisterValidation("e164", validateE164)
	_ = v.RegisterValidation("iso3166_1_alpha2", validateISO3166Alpha2)

	return &CustomValidator{validator: v}
}

// Validate validates a struct
func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

// E164 regex (simple version: + followed by 1-15 digits)
var e164Regex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

func validateE164(fl validator.FieldLevel) bool {
	return e164Regex.MatchString(fl.Field().String())
}

// ISO 3166-1 Alpha-2 regex (2 uppercase letters)
var iso3166Regex = regexp.MustCompile(`^[A-Z]{2}$`)

func validateISO3166Alpha2(fl validator.FieldLevel) bool {
	return iso3166Regex.MatchString(fl.Field().String())
}
