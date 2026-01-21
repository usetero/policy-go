package policy

import (
	"errors"
	"fmt"
)

// ErrorKind categorizes policy errors.
type ErrorKind int

const (
	// ErrInvalidPolicy indicates a policy failed validation.
	ErrInvalidPolicy ErrorKind = iota
	// ErrCompilation indicates pattern compilation failed.
	ErrCompilation
	// ErrProvider indicates a provider operation failed.
	ErrProvider
	// ErrEvaluation indicates evaluation failed.
	ErrEvaluation
)

func (k ErrorKind) String() string {
	switch k {
	case ErrInvalidPolicy:
		return "invalid policy"
	case ErrCompilation:
		return "compilation error"
	case ErrProvider:
		return "provider error"
	case ErrEvaluation:
		return "evaluation error"
	default:
		return "unknown error"
	}
}

// PolicyError represents an error in policy operations.
type PolicyError struct {
	Kind    ErrorKind
	Message string
	Cause   error
}

func (e *PolicyError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

func (e *PolicyError) Unwrap() error {
	return e.Cause
}

// NewError creates a new PolicyError.
func NewError(kind ErrorKind, message string) *PolicyError {
	return &PolicyError{Kind: kind, Message: message}
}

// WrapError creates a new PolicyError wrapping an existing error.
func WrapError(kind ErrorKind, message string, cause error) *PolicyError {
	return &PolicyError{Kind: kind, Message: message, Cause: cause}
}

// IsInvalidPolicy returns true if the error is an invalid policy error.
func IsInvalidPolicy(err error) bool {
	var pErr *PolicyError
	return errors.As(err, &pErr) && pErr.Kind == ErrInvalidPolicy
}

// IsCompilation returns true if the error is a compilation error.
func IsCompilation(err error) bool {
	var pErr *PolicyError
	return errors.As(err, &pErr) && pErr.Kind == ErrCompilation
}

// IsProvider returns true if the error is a provider error.
func IsProvider(err error) bool {
	var pErr *PolicyError
	return errors.As(err, &pErr) && pErr.Kind == ErrProvider
}

// IsEvaluation returns true if the error is an evaluation error.
func IsEvaluation(err error) bool {
	var pErr *PolicyError
	return errors.As(err, &pErr) && pErr.Kind == ErrEvaluation
}
