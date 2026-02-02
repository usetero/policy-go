package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInvalidPolicy(t *testing.T) {
	// Test IsInvalidPolicy returns true for invalid policy errors
	err := NewError(ErrInvalidPolicy, "policy has no matchers")
	assert.True(t, IsInvalidPolicy(err), "IsInvalidPolicy should return true for ErrInvalidPolicy")

	// Test it returns false for other error types
	err = NewError(ErrCompilation, "regex compilation failed")
	assert.False(t, IsInvalidPolicy(err), "IsInvalidPolicy should return false for ErrCompilation")

	// Test it returns false for wrapped errors of different types
	err = WrapError(ErrProvider, "failed to load", nil)
	assert.False(t, IsInvalidPolicy(err), "IsInvalidPolicy should return false for ErrProvider")

	// Test it returns false for non-PolicyError
	assert.False(t, IsInvalidPolicy(assert.AnError), "IsInvalidPolicy should return false for non-PolicyError")
}

func TestIsCompilation(t *testing.T) {
	// Test IsCompilation returns true for compilation errors
	err := NewError(ErrCompilation, "invalid regex pattern")
	assert.True(t, IsCompilation(err), "IsCompilation should return true for ErrCompilation")

	// Test it returns false for other error types
	err = NewError(ErrInvalidPolicy, "missing field")
	assert.False(t, IsCompilation(err), "IsCompilation should return false for ErrInvalidPolicy")

	// Test it returns false for non-PolicyError
	assert.False(t, IsCompilation(assert.AnError), "IsCompilation should return false for non-PolicyError")
}

func TestIsEvaluation(t *testing.T) {
	// Test IsEvaluation returns true for evaluation errors
	err := NewError(ErrEvaluation, "evaluation failed")
	assert.True(t, IsEvaluation(err), "IsEvaluation should return true for ErrEvaluation")

	// Test it returns false for other error types
	err = NewError(ErrProvider, "provider error")
	assert.False(t, IsEvaluation(err), "IsEvaluation should return false for ErrProvider")

	// Test it returns false for non-PolicyError
	assert.False(t, IsEvaluation(assert.AnError), "IsEvaluation should return false for non-PolicyError")
}

func TestIsProvider(t *testing.T) {
	// Test IsProvider returns true for provider errors
	err := NewError(ErrProvider, "failed to connect")
	assert.True(t, IsProvider(err), "IsProvider should return true for ErrProvider")

	// Test it returns false for other error types
	err = NewError(ErrEvaluation, "evaluation error")
	assert.False(t, IsProvider(err), "IsProvider should return false for ErrEvaluation")

	// Test it returns false for non-PolicyError
	assert.False(t, IsProvider(assert.AnError), "IsProvider should return false for non-PolicyError")
}

func TestPolicyErrorUnwrap(t *testing.T) {
	// Test that Unwrap returns the wrapped cause
	cause := assert.AnError
	err := WrapError(ErrCompilation, "compilation failed", cause)

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped, "Unwrap should return the wrapped cause")

	// Test that Unwrap returns nil when there is no cause
	errNoCause := NewError(ErrInvalidPolicy, "no cause")
	assert.Nil(t, errNoCause.Unwrap(), "Unwrap should return nil when there is no cause")
}

func TestPolicyErrorString(t *testing.T) {
	// Test error string with cause
	cause := assert.AnError
	err := WrapError(ErrCompilation, "compilation failed", cause)
	assert.Contains(t, err.Error(), "compilation error")
	assert.Contains(t, err.Error(), "compilation failed")
	assert.Contains(t, err.Error(), cause.Error())

	// Test error string without cause
	errNoCause := NewError(ErrInvalidPolicy, "policy is invalid")
	assert.Contains(t, errNoCause.Error(), "invalid policy")
	assert.Contains(t, errNoCause.Error(), "policy is invalid")
}

func TestErrorKindString(t *testing.T) {
	assert.Equal(t, "invalid policy", ErrInvalidPolicy.String())
	assert.Equal(t, "compilation error", ErrCompilation.String())
	assert.Equal(t, "provider error", ErrProvider.String())
	assert.Equal(t, "evaluation error", ErrEvaluation.String())
	assert.Equal(t, "unknown error", ErrorKind(999).String())
}
