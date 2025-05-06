package cego

import (
	"github.com/stretchr/testify/mock"
)

// Interface guard
var _ Logger = (*MockLogger)(nil)

type MockLogger struct {
	mock.Mock
}

func NewMockLogger() *MockLogger {
	m := &MockLogger{}
	m.On("Debug", mock.Anything, mock.Anything).Return(nil)
	m.On("Error", mock.Anything, mock.Anything).Return(nil)
	return m
}

func (l *MockLogger) Debug(message string, args ...any) {
	l.Called(message, args)
}

func (l *MockLogger) Info(message string, args ...any) {
	l.Called(message, args)
}

func (l *MockLogger) Error(message string, args ...any) {
	l.Called(message, args)
}
