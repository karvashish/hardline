package logger

type wrappedError struct {
	msg string
	err error
}

func (e wrappedError) Error() string {
	if e.err == nil {
		return e.msg
	}
	if e.msg == "" {
		return e.err.Error()
	}
	return e.msg + ": " + e.err.Error()
}

func (e wrappedError) Unwrap() error {
	return e.err
}

func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return wrappedError{msg: msg, err: err}
}
