package middleware

import (
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

// Global validator instance
var validate = validator.New()

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ValidateStruct validates a struct and returns formatted errors
func ValidateStruct(s interface{}) []ValidationError {
	var errors []ValidationError

	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			var element ValidationError
			element.Field = strings.ToLower(err.StructField())
			element.Tag = err.Tag()
			element.Value = err.Param()
			element.Message = getErrorMessage(err)
			errors = append(errors, element)
		}
	}

	return errors
}

// getErrorMessage returns a human-readable error message
func getErrorMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	case "min":
		return "This field must be at least " + fe.Param() + " characters long"
	case "max":
		return "This field must be at most " + fe.Param() + " characters long"
	case "gte":
		return "This field must be greater than or equal to " + fe.Param()
	case "lte":
		return "This field must be less than or equal to " + fe.Param()
	default:
		return "Invalid value for this field"
	}
}

// ValidateRequest middleware validates request bodies
func ValidateRequest(model interface{}) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Create a new instance of the model type
		modelType := reflect.TypeOf(model)
		if modelType.Kind() == reflect.Ptr {
			modelType = modelType.Elem()
		}

		newModel := reflect.New(modelType).Interface()

		// Parse request body
		if err := c.BodyParser(newModel); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request body",
			})
		}

		// Validate the model
		if errors := ValidateStruct(newModel); len(errors) > 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Validation failed",
				"details": errors,
			})
		}

		// Store validated data in context
		c.Locals("validated_data", newModel)

		return c.Next()
	}
}

// ValidatePathParams validates path parameters
func ValidatePathParams(rules map[string]string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		errors := []ValidationError{}

		for param, rule := range rules {
			value := c.Params(param)

			switch rule {
			case "uuid":
				if len(value) != 36 || !isValidUUID(value) {
					errors = append(errors, ValidationError{
						Field:   param,
						Tag:     "uuid",
						Value:   value,
						Message: "Invalid UUID format",
					})
				}
			case "required":
				if value == "" {
					errors = append(errors, ValidationError{
						Field:   param,
						Tag:     "required",
						Value:   value,
						Message: "This parameter is required",
					})
				}
			}
		}

		if len(errors) > 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Invalid path parameters",
				"details": errors,
			})
		}

		return c.Next()
	}
}

// Helper function to validate UUID format
func isValidUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}

	// Simple UUID pattern check
	for i, c := range uuid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}

	return true
}
