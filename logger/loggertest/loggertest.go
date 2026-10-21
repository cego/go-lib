package loggertest

import (
	"github.com/cego/go-lib/v2/logger"
	"github.com/stretchr/testify/mock"
)

var _ logger.Logger = (*Mock)(nil)

type Mock struct {
	mock.Mock
}

func NewMock() *Mock {
	m := &Mock{}
	m.On("Debug", mock.Anything, mock.Anything).Return(nil)
	m.On("Info", mock.Anything, mock.Anything).Return(nil)
	m.On("Error", mock.Anything, mock.Anything).Return(nil)
	return m
}

func (l *Mock) Debug(message string, args ...any) {
	l.Called(message, args)
}

func (l *Mock) Info(message string, args ...any) {
	l.Called(message, args)
}

func (l *Mock) Error(message string, args ...any) {
	l.Called(message, args)
}
